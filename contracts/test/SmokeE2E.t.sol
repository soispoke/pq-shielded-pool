// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {RecentRoots} from "../src/RecentRoots.sol";
import {AttestedVerifier} from "../src/AttestedVerifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";

interface Vm {
    function readFile(string calldata) external view returns (string memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseBytes32(string calldata) external pure returns (bytes32);
    function sign(uint256, bytes32) external pure returns (uint8, bytes32, bytes32);
    function addr(uint256) external pure returns (address);
    function prank(address) external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function parseAddress(string calldata) external pure returns (address);
    function expectRevert() external;
}

/// The whole stack in one in-process EVM run: deploy, shield Alice's note, run
/// her REAL-proof transfer to Bob, then Bob's REAL-proof withdraw, and assert
/// the payout and double-spend rejection. The claims, roots, and proof hashes
/// come from wallet/smoke_fixture.json, produced by wallet/gen_smoke.py, which
/// built the witnesses from the reconstructed tree, proved them with leanVM,
/// and verified each proof off-chain. What this test adds: the pool's tree
/// republishes exactly the roots the wallet computed (asserted), and the pool
/// accepts the real claims through the attester shim. The attester signature
/// stands in for the leanVM-verify precompile a real devnet supplies.
///
/// The fixture is committed and deterministic (seeded notes), so `forge test`
/// runs this unaided; wallet/smoke.sh regenerates it with fresh proofs.
contract SmokeE2ETest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 constant ATTESTER_PK = 0xA11CE;
    address constant POOL_SENDER = address(0x5EEDED);
    uint256 constant DENOM = 1 ether;
    string constant FIX = "../wallet/smoke_fixture.json";

    ShieldedPool pool;
    AttestedVerifier verifier;
    string j;

    function setUp() public {
        vm.roll(1000);
        RecentRoots roots = new RecentRoots();
        verifier = new AttestedVerifier(vm.addr(ATTESTER_PK));
        pool = new ShieldedPool(DENOM, POOL_SENDER, roots, verifier);
        vm.deal(address(this), 10 ether);
        vm.deal(POOL_SENDER, 10 ether);
        j = vm.readFile(FIX);
    }

    function _s(string memory key) internal view returns (bytes32) {
        return vm.parseBytes32(vm.parseJsonString(j, key));
    }

    function _spend(string memory p, uint64 slot) internal view returns (ShieldedPool.Spend memory s) {
        bytes32 claim = _s(string.concat(p, ".claim"));
        bytes32 proofHash = _s(string.concat(p, ".proof_hash"));
        bytes32 d = verifier.attestationDigest(address(pool), claim, proofHash);
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(ATTESTER_PK, d);
        s = ShieldedPool.Spend({
            root: _s(string.concat(p, ".root")),
            slot: slot,
            nf: _s(string.concat(p, ".nf")),
            outCm: _s(string.concat(p, ".out_cm")),
            ctx: _s(string.concat(p, ".ctx")),
            proofHash: proofHash,
            attestation: abi.encodePacked(r, sig, v)
        });
    }

    function test_end_to_end_real_proofs() public {
        // 1. Alice shields cm_A; its root R1 is published this block
        pool.shield{value: DENOM}(_s(".cm_a"));
        uint64 slotR1 = pool.lastRootSlot();
        require(pool.currentRoot() == _s(".transfer.root"),
                "pool root after shield != wallet's transfer root");
        vm.roll(slotR1 + 1); // R1 referenceable from S+1

        // 2. Alice's real-proof transfer to Bob (appends cm_B, publishes R2)
        ShieldedPool.Spend memory ts = _spend(".transfer", slotR1);
        vm.prank(POOL_SENDER);
        pool.transfer(ts);
        uint64 slotR2 = pool.lastRootSlot();
        require(pool.currentRoot() == _s(".withdraw.root"),
                "pool root after transfer != wallet's withdraw root");
        require(pool.isLeaf(ts.outCm), "cm_B not appended");
        vm.roll(slotR2 + 1); // R2 referenceable from S+1

        // 3. Bob's real-proof withdraw to the recipient
        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        uint256 balBefore = recipient.balance;
        ShieldedPool.Spend memory ws = _spend(".withdraw", slotR2);
        vm.prank(POOL_SENDER);
        pool.withdraw(ws, recipient);

        require(recipient.balance == balBefore + DENOM, "recipient not paid");
        require(pool.nonces().current(POOL_SENDER, ts.nf) == 1, "transfer nf not consumed");
        require(pool.nonces().current(POOL_SENDER, ws.nf) == 1, "withdraw nf not consumed");

        // 4. a replay of Bob's withdraw is refused (nullifier already spent)
        vm.prank(POOL_SENDER);
        vm.expectRevert();
        pool.withdraw(ws, recipient);
    }
}
