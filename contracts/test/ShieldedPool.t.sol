// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Poseidon16} from "../src/Poseidon16.sol";
import {NonceManager} from "../src/NonceManager.sol";
import {RecentRoots} from "../src/RecentRoots.sol";
import {AttestedVerifier} from "../src/AttestedVerifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";

interface Vm {
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function sign(uint256, bytes32) external pure returns (uint8, bytes32, bytes32);
    function addr(uint256) external pure returns (address);
    function expectRevert(bytes4) external;
    function expectRevert() external;
    function readFile(string calldata) external view returns (string memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseBytes32(string calldata) external pure returns (bytes32);
    function toString(uint256) external pure returns (string memory);
}

/// Ports pool/envelope.py's attack battery to the on-chain contracts, plus the
/// cross-stack fixtures (ctxFor, computeClaim, incremental tree root) checked
/// against values the leanVM prover / Python reference produced. The leanVM
/// STARK is represented by the AttestedVerifier shim: a valid spend carries an
/// attester signature over its claim, exactly the trust boundary devnet
/// deletes. What is tested here is the pool's binding logic, not the proof.
contract ShieldedPoolTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ShieldedPool pool;
    NonceManager nonces;
    RecentRoots roots;
    AttestedVerifier verifier;

    uint256 constant ATTESTER_PK = 0xA11CE;
    address constant POOL_SENDER = address(0x5EEDED);
    uint256 constant DENOM = 1 ether;

    function setUp() public {
        vm.roll(1000);
        roots = new RecentRoots();
        verifier = new AttestedVerifier(vm.addr(ATTESTER_PK));
        pool = new ShieldedPool(DENOM, POOL_SENDER, roots, verifier);
        nonces = pool.nonces();
        vm.deal(address(this), 100 ether);
        vm.deal(POOL_SENDER, 1 ether);
    }

    // ---- helpers ----

    function _digest(uint256 seed) internal pure returns (bytes32) {
        // 8 words each < P, so a valid (canonical) digest
        uint256 acc;
        for (uint256 i = 0; i < 8; i++) {
            acc = (acc << 32) | (uint256(keccak256(abi.encode(seed, i))) % Poseidon16.P);
        }
        return bytes32(acc);
    }

    function _attest(bytes32 claim, bytes32 proofHash) internal view returns (bytes memory) {
        bytes32 digest = verifier.attestationDigest(address(pool), claim, proofHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ATTESTER_PK, digest);
        return abi.encodePacked(r, s, v);
    }

    /// A shield that returns the root the pool published and the slot it landed in.
    function _shield(bytes32 cm) internal returns (bytes32 root, uint64 slot) {
        pool.shield{value: DENOM}(cm);
        root = pool.currentRoot();
        slot = uint64(block.number);
        vm.roll(block.number + 1); // a root written in slot S is usable from S+1
    }

    function _spend(bytes32 root, uint64 slot, bytes32 nf, bytes32 outCm, bytes32 ctx)
        internal
        view
        returns (ShieldedPool.Spend memory s)
    {
        bytes32 claim = pool.computeClaim(root, nf, outCm, ctx);
        bytes32 proofHash = keccak256(abi.encode("proof", nf));
        s = ShieldedPool.Spend(root, slot, nf, outCm, ctx, proofHash, _attest(claim, proofHash));
    }

    // ---- 1. honest transfer through the pinned sender ----

    function test_transfer_via_pinned_sender() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        bytes32 outCm = _digest(200);
        ShieldedPool.Spend memory s = _spend(root, slot, nf, outCm, bytes32(0));
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        assertTrue(nonces.current(POOL_SENDER, nf) == 1, "key consumed");
        assertTrue(pool.isLeaf(outCm), "recipient note appended");
    }

    // ---- 2. same-sender double-spend ----

    function test_double_spend_same_sender_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        ShieldedPool.Spend memory s = _spend(root, slot, nf, _digest(200), bytes32(0));
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        ShieldedPool.Spend memory s2 = _spend(root, slot, nf, _digest(201), bytes32(0));
        vm.prank(POOL_SENDER);
        vm.expectRevert(NonceManager.NonceKeyAlreadyUsed.selector);
        pool.transfer(s2);
    }

    // ---- 3. cross-sender double-spend: the attack pinning exists to stop ----

    function test_cross_sender_double_spend_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        ShieldedPool.Spend memory s = _spend(root, slot, nf, _digest(200), bytes32(0));
        vm.prank(POOL_SENDER);
        pool.transfer(s);

        // the protocol alone treats (eve, nf) as fresh...
        assertTrue(nonces.current(address(0xEEEE), nf) == 0, "eve's slot is fresh");
        // ...only the pinned-sender check refuses eve's frame
        ShieldedPool.Spend memory s2 = _spend(root, slot, nf, _digest(202), bytes32(0));
        vm.prank(address(0xEEEE));
        vm.expectRevert(ShieldedPool.NotPoolSender.selector);
        pool.transfer(s2);
    }

    // ---- 4. lifted-proof / envelope attacks ----

    function test_zero_nullifier_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        ShieldedPool.Spend memory s = _spend(root, slot, bytes32(0), _digest(200), bytes32(0));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ZeroNullifier.selector);
        pool.transfer(s);
    }

    function test_unattested_proof_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        bytes32 outCm = _digest(200);
        bytes32 claim = pool.computeClaim(root, nf, outCm, bytes32(0));
        // sign with the WRONG key
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(0xBAD, verifier.attestationDigest(address(pool), claim, bytes32(0)));
        ShieldedPool.Spend memory s =
            ShieldedPool.Spend(root, slot, nf, outCm, bytes32(0), bytes32(0), abi.encodePacked(r, sg, v));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofNotAttested.selector);
        pool.transfer(s);
    }

    // ---- 5. root-source / freshness attacks ----

    function test_foreign_root_reverts() public {
        _shield(_digest(1));
        bytes32 nf = _digest(100);
        // a root the pool never published
        bytes32 fakeRoot = _digest(999);
        ShieldedPool.Spend memory s = _spend(fakeRoot, uint64(block.number - 1), nf, _digest(200), bytes32(0));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotRecentForPool.selector);
        pool.transfer(s);
    }

    function test_stale_root_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        // advance beyond the usable window
        vm.roll(slot + roots.RECENT_ROOT_USABLE_WINDOW() + 1);
        ShieldedPool.Spend memory s = _spend(root, slot, nf, _digest(200), bytes32(0));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotRecentForPool.selector);
        pool.transfer(s);
    }

    // ---- 6. operation-shape attacks ----

    function test_transfer_and_withdraw_in_one_spend_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        // both outCm and ctx nonzero: neither shape accepts it
        ShieldedPool.Spend memory s = _spend(root, slot, nf, _digest(200), _digest(300));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.TransferShape.selector);
        pool.transfer(s);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.WithdrawShape.selector);
        pool.withdraw(s, payable(address(0xBEEF)));
    }

    // ---- 6c. duplicate output is a no-op success, never a revert ----

    function test_duplicate_output_is_noop() public {
        // pre-seed outCm as an existing leaf (the front-run)
        bytes32 outCm = _digest(200);
        pool.shield{value: DENOM}(outCm);
        vm.roll(block.number + 1);
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        uint32 before = pool.nextIndex();
        ShieldedPool.Spend memory s = _spend(root, slot, nf, outCm, bytes32(0));
        vm.prank(POOL_SENDER);
        pool.transfer(s); // must not revert
        assertTrue(nonces.current(POOL_SENDER, nf) == 1, "nf still consumed");
        assertTrue(pool.nextIndex() == before, "no leaf appended");
    }

    // ---- withdraw pays out and consumes ----

    function test_withdraw_pays_out() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 nf = _digest(100);
        address payable recipient = payable(address(0xCAFE));
        bytes32 ctx = pool.ctxFor(recipient);
        ShieldedPool.Spend memory s = _spend(root, slot, nf, bytes32(0), ctx);
        uint256 balBefore = recipient.balance;
        vm.prank(POOL_SENDER);
        pool.withdraw(s, recipient);
        assertTrue(recipient.balance == balBefore + DENOM, "recipient paid");
        assertTrue(nonces.current(POOL_SENDER, nf) == 1, "nf consumed");
    }

    function test_withdraw_wrong_recipient_reverts() public {
        (bytes32 root, uint64 slot) = _shield(_digest(1));
        bytes32 ctx = pool.ctxFor(address(0xCAFE));
        ShieldedPool.Spend memory s = _spend(root, slot, _digest(100), bytes32(0), ctx);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.CtxDoesNotNameRecipient.selector);
        pool.withdraw(s, payable(address(0xDEAD))); // ctx names 0xCAFE
    }

    // ---- shield rules ----

    function test_shield_wrong_denomination_reverts() public {
        vm.expectRevert(ShieldedPool.WrongDenomination.selector);
        pool.shield{value: 0.5 ether}(_digest(1));
    }

    function test_shield_duplicate_commitment_reverts() public {
        bytes32 cm = _digest(1);
        pool.shield{value: DENOM}(cm);
        vm.expectRevert(ShieldedPool.DuplicateCommitment.selector);
        pool.shield{value: DENOM}(cm);
    }

    // ---- cross-stack fixtures (leanVM prover / Python reference) ----

    function test_ctxFor_matches_prover() public view {
        string memory json = vm.readFile("vectors/pool_fixtures.json");
        bytes32 expected = vm.parseBytes32(vm.parseJsonString(json, ".ctx_cafebabe"));
        assertTrue(pool.ctxFor(address(0xcafebabe)) == expected, "ctxFor mismatch vs prover");
    }

    function test_computeClaim_matches_prover() public view {
        string memory json = vm.readFile("vectors/pool_fixtures.json");
        bytes32 root = vm.parseBytes32(vm.parseJsonString(json, ".claim_case.root"));
        bytes32 nf = vm.parseBytes32(vm.parseJsonString(json, ".claim_case.nf"));
        bytes32 outCm = vm.parseBytes32(vm.parseJsonString(json, ".claim_case.out_cm"));
        bytes32 ctx = vm.parseBytes32(vm.parseJsonString(json, ".claim_case.ctx"));
        bytes32 expected = vm.parseBytes32(vm.parseJsonString(json, ".claim_case.claim"));
        assertTrue(pool.computeClaim(root, nf, outCm, ctx) == expected, "computeClaim mismatch vs prover");
    }

    function test_tree_root_matches_reference() public {
        string memory json = vm.readFile("vectors/pool_fixtures.json");
        // empty-tree root (pool computed it at construction) vs the reference
        assertTrue(
            pool.currentRoot() == vm.parseBytes32(vm.parseJsonString(json, ".tree.root_empty")),
            "empty root mismatch vs reference"
        );
        bytes32 cm0 = vm.parseBytes32(vm.parseJsonString(json, ".tree.cm0"));
        bytes32 cm1 = vm.parseBytes32(vm.parseJsonString(json, ".tree.cm1"));
        pool.shield{value: DENOM}(cm0);
        assertTrue(
            pool.currentRoot() == vm.parseBytes32(vm.parseJsonString(json, ".tree.root_after_cm0")),
            "root after cm0 mismatch vs reference"
        );
        pool.shield{value: DENOM}(cm1);
        assertTrue(
            pool.currentRoot() == vm.parseBytes32(vm.parseJsonString(json, ".tree.root_after_cm0_cm1")),
            "root after cm0,cm1 mismatch vs reference"
        );
    }

    // minimal assert
    function assertTrue(bool c, string memory m) internal pure {
        require(c, m);
    }
}
