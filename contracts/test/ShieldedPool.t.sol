// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "../src/PoseidonBN254.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {NonceManager} from "../src/NonceManager.sol";
import {RecentRoots} from "../src/RecentRoots.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function expectRevert(bytes4) external;
    function readFile(string calldata) external view returns (string memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseJsonStringArray(string calldata, string calldata) external pure returns (string[] memory);
    function parseBytes32(string calldata) external pure returns (bytes32);
    function parseAddress(string calldata) external pure returns (address);
    function parseUint(string calldata) external pure returns (uint256);
}

/// The attack battery for the JOIN-SPLIT pool. Every accepted spend carries a
/// real Groth16 proof (wallet/smoke_fixture.json) verified on-chain, spends
/// consume their two nullifiers as one EIP-8250 key set, and fees are paid to
/// the submitter from shielded value. The star witness is `attack_same_note`:
/// a REAL, circuit-valid proof that spends one note through both inputs
/// (nf1 == nf2, conservation satisfied at double the value). Nothing in the
/// proof layer refuses it; the multi-key set consumption must, and does.
contract ShieldedPoolBN254Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ShieldedPool pool;
    NonceManager nonces;
    RecentRoots roots;
    Groth16Verifier verifier;
    string j;

    address constant POOL_SENDER = address(0x5EEDED);
    string constant FIX = "../wallet/smoke_fixture.json";

    event log_named_uint(string key, uint256 val); // decoded by forge at -vv

    function setUp() public {
        vm.roll(1000);
        roots = new RecentRoots();
        verifier = new Groth16Verifier();
        pool = new ShieldedPool(POOL_SENDER, roots, verifier);
        nonces = pool.nonces();
        vm.deal(address(this), 100 ether);
        vm.deal(POOL_SENDER, 1 ether);
        j = vm.readFile(FIX);
    }

    // ---- fixture helpers ----

    function _s(string memory key) internal view returns (bytes32) {
        return vm.parseBytes32(vm.parseJsonString(j, key));
    }

    function _u(string memory key) internal view returns (uint256) {
        return vm.parseUint(vm.parseJsonString(j, key));
    }

    function _pair(string memory key) internal view returns (uint256[2] memory out) {
        string[] memory v = vm.parseJsonStringArray(j, key);
        out[0] = uint256(vm.parseBytes32(v[0]));
        out[1] = uint256(vm.parseBytes32(v[1]));
    }

    function _spendOf(string memory p, uint64 slot) internal view returns (ShieldedPool.Spend memory s) {
        s = ShieldedPool.Spend({
            root: _s(string.concat(p, ".root")),
            slot: slot,
            nf1: _s(string.concat(p, ".nf1")),
            nf2: _s(string.concat(p, ".nf2")),
            outCm1: _s(string.concat(p, ".out_cm1")),
            outCm2: _s(string.concat(p, ".out_cm2")),
            publicAmount: _u(string.concat(p, ".public_amount")),
            fee: _u(string.concat(p, ".fee")),
            ctx: _s(string.concat(p, ".ctx")),
            pA: _pair(string.concat(p, ".proof.pA")),
            pB: [_pair(string.concat(p, ".proof.pB[0]")), _pair(string.concat(p, ".proof.pB[1]"))],
            pC: _pair(string.concat(p, ".proof.pC"))
        });
    }

    /// Shield Alice's 1.0-ether note so the pool's tree matches the fixture's
    /// transfer root, and return the fixture transfer spend for that slot.
    function _shieldA() internal returns (ShieldedPool.Spend memory ts) {
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        uint64 slot = pool.lastRootSlot();
        require(pool.isLeaf(_s(".cm_a")), "shield hashed the wrong commitment");
        require(pool.currentRoot() == _s(".transfer.root"),
                "pool root after shield != wallet's transfer root");
        vm.roll(block.number + 1); // a root written in slot S is usable from S+1
        ts = _spendOf(".transfer", slot);
    }

    // ---- 1. honest join-split transfer: two nullifiers, ONE key set ----

    function test_transfer_consumes_both_keys_as_one_set() public {
        ShieldedPool.Spend memory s = _shieldA();
        uint256 senderBefore = POOL_SENDER.balance;
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        assertTrue(nonces.current(POOL_SENDER, s.nf1) == 1, "nf1 consumed");
        assertTrue(nonces.current(POOL_SENDER, s.nf2) == 1, "nf2 consumed");
        assertTrue(pool.isLeaf(s.outCm1) && pool.isLeaf(s.outCm2), "both outputs appended");
        assertTrue(POOL_SENDER.balance == senderBefore + s.fee, "fee paid to submitter");
        assertTrue(pool.currentRoot() == _s(".withdraw.root"),
                   "pool root after transfer != wallet's withdraw root");
    }

    // ---- 2. the multi-key star witness: one note through both inputs ----

    function test_same_note_both_inputs_reverts_in_key_set() public {
        // this proof is REAL and circuit-valid (conservation holds at twice
        // the note's value); only the EIP-8250 duplicate-key rule refuses it
        ShieldedPool.Spend memory s = _shieldA();
        ShieldedPool.Spend memory x = _spendOf(".attack_same_note", s.slot);
        assertTrue(x.nf1 == x.nf2, "the attack exposes one nullifier twice");
        vm.prank(POOL_SENDER);
        vm.expectRevert(NonceManager.NonceKeyAlreadyUsed.selector);
        pool.transfer(x);
        assertTrue(nonces.current(POOL_SENDER, x.nf1) == 0, "atomic: nothing consumed");
    }

    // ---- 3. replay and cross-sender double-spends ----

    function test_double_spend_replay_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        vm.roll(block.number + 1);
        vm.prank(POOL_SENDER);
        vm.expectRevert(NonceManager.NonceKeyAlreadyUsed.selector);
        pool.transfer(s);
    }

    function test_cross_sender_double_spend_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        assertTrue(nonces.current(address(0xEEEE), s.nf1) == 0, "eve's slot is fresh");
        vm.prank(address(0xEEEE));
        vm.expectRevert(ShieldedPool.NotPoolSender.selector);
        pool.transfer(s);
    }

    // ---- 4. proof attacks ----

    function test_zero_nullifier_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf2 = bytes32(0);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ZeroNullifier.selector);
        pool.transfer(s);
    }

    function test_corrupted_proof_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.pA[0] = addmod(s.pA[0], 1, 21888242871839275222246405745257275088696311157297823662689037894645226208583);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.transfer(s);
    }

    /// A valid proof cannot have its amounts re-priced: fee and publicAmount
    /// are public signals the proof binds, so tampering kills the proof.
    function test_tampered_fee_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.fee = s.fee + 1;
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.transfer(s);
    }

    function test_tampered_outputs_revert() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.outCm1 = bytes32(uint256(12345));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.transfer(s);
    }

    /// The root is bound by the PROOF, not only by the recent-roots check:
    /// anchor the fixture proof to a second, genuinely recent root so
    /// roots.check passes and only the verifier stands in the way. Catches a
    /// circuit regression that drops root from the public list.
    function test_recent_but_unproven_root_reverts_in_verifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        s.root = pool.currentRoot();
        s.slot = pool.lastRootSlot();
        vm.roll(block.number + 1);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.transfer(s);
    }

    /// ctx and publicAmount are bound by the PROOF, not only by the shape
    /// checks: re-bind the withdraw to a different recipient CONSISTENTLY
    /// (ctx = ctxFor(evil), so CtxDoesNotNameRecipient passes), and re-price
    /// the payout. Catches a circuit regression that drops either from the
    /// public list.
    function test_rebound_ctx_and_repriced_amount_revert_in_verifier() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(ts);
        uint64 slotR2 = pool.lastRootSlot();
        vm.roll(block.number + 1);

        ShieldedPool.Spend memory ws = _spendOf(".withdraw", slotR2);
        address payable evil = payable(address(0xBEEF));
        ws.ctx = pool.ctxFor(evil);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.withdraw(ws, evil);

        ShieldedPool.Spend memory wp = _spendOf(".withdraw", slotR2);
        wp.publicAmount = wp.publicAmount + 1;
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.withdraw(wp, payable(vm.parseAddress(vm.parseJsonString(j, ".recipient"))));
    }

    // ---- 5. root-source / freshness attacks ----

    function test_foreign_root_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.root = bytes32(uint256(999));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotRecentForPool.selector);
        pool.transfer(s);
    }

    function test_stale_root_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.roll(uint256(s.slot) + roots.RECENT_ROOT_USABLE_WINDOW() + 1);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotRecentForPool.selector);
        pool.transfer(s);
    }

    // ---- 6. operation-shape attacks ----

    function test_withdraw_shaped_spend_rejected_by_transfer() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.publicAmount = 1; // nonzero publicAmount is not a transfer
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.TransferShape.selector);
        pool.transfer(s);
    }

    function test_transfer_shaped_spend_rejected_by_withdraw() public {
        ShieldedPool.Spend memory s = _shieldA(); // publicAmount == 0, ctx == 0
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.WithdrawShape.selector);
        pool.withdraw(s, payable(address(0xBEEF)));
    }

    // ---- 6c. duplicate output is a no-op success, never a revert ----

    function test_duplicate_output_is_noop() public {
        ShieldedPool.Spend memory s = _shieldA();
        // the recipient's opening is known here (fixture), so pre-create the
        // exact output commitment via shield
        pool.shield{value: _u(".transfer.out_value1")}(_s(".transfer.out_inner1"));
        require(pool.isLeaf(s.outCm1), "pre-seeded output leaf");
        vm.roll(block.number + 1);
        uint32 before = pool.nextIndex();
        vm.prank(POOL_SENDER);
        pool.transfer(s); // must not revert
        assertTrue(nonces.current(POOL_SENDER, s.nf1) == 1, "nf1 still consumed");
        assertTrue(pool.nextIndex() == before + 1, "only the change note appended");
    }

    // ---- withdraw: full real-proof lifecycle with fees ----

    function test_full_lifecycle_pays_recipient_fees_and_stays_solvent() public {
        ShieldedPool.Spend memory ts = _shieldA();
        uint256 senderBefore = POOL_SENDER.balance;
        vm.prank(POOL_SENDER);
        pool.transfer(ts);
        uint64 slotR2 = pool.lastRootSlot();
        vm.roll(block.number + 1);

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw", slotR2);
        uint256 balBefore = recipient.balance;
        vm.prank(POOL_SENDER);
        pool.withdraw(ws, recipient);

        assertTrue(recipient.balance == balBefore + ws.publicAmount, "recipient paid publicAmount");
        assertTrue(POOL_SENDER.balance == senderBefore + ts.fee + ws.fee,
                   "submitter reimbursed both fees from shielded value");
        // solvency: 1.0 in, 0.55 out, 0.1 fees out; Alice's 0.35 change remains
        assertTrue(address(pool).balance ==
                   _u(".shield_value") - ws.publicAmount - ts.fee - ws.fee,
                   "pool balance equals the one unspent change note");
    }

    function test_withdraw_wrong_recipient_reverts() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(ts);
        uint64 slotR2 = pool.lastRootSlot();
        vm.roll(block.number + 1);
        ShieldedPool.Spend memory ws = _spendOf(".withdraw", slotR2);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.CtxDoesNotNameRecipient.selector);
        pool.withdraw(ws, payable(address(0xDEAD)));
    }

    // ---- shield rules ----

    function test_shield_zero_value_reverts() public {
        vm.expectRevert(ShieldedPool.ZeroValueShield.selector);
        pool.shield{value: 0}(bytes32(uint256(1)));
    }

    function test_shield_duplicate_commitment_reverts() public {
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        vm.expectRevert(ShieldedPool.DuplicateCommitment.selector);
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        // same inner at a DIFFERENT value is a different commitment: allowed
        pool.shield{value: 2 ether}(bytes32(uint256(1)));
    }

    function test_shield_noncanonical_reverts() public {
        vm.expectRevert(ShieldedPool.NotCanonical.selector);
        pool.shield{value: 1 ether}(bytes32(type(uint256).max));
    }

    // ---- cross-stack fixtures (wallet / Python reference) ----

    function test_ctxFor_matches_wallet() public view {
        assertTrue(pool.ctxFor(address(0xcafebabe)) == _s(".withdraw.ctx"),
                   "ctxFor mismatch vs wallet");
    }

    function test_tree_root_matches_reference() public {
        string memory vecs = vm.readFile("../vectors/poseidon_bn254_vectors.json");
        assertTrue(
            uint256(pool.currentRoot()) == vm.parseUint(vm.parseJsonString(vecs, ".tree.root_empty")),
            "empty root mismatch vs reference"
        );
        // shield can't append arbitrary leaves (it hashes value in), so check
        // the incremental tree through the reference fixture's raw leaves via
        // the wallet-side root equalities asserted in _shieldA and the
        // lifecycle test; here, assert the empty root only.
    }

    // ---- VERIFY-frame readiness (for a devnet that raises MAX_VERIFY_GAS and
    //      exposes a nonce_keys TXPARAM selector) ----

    /// verifySpend must run under STATICCALL, so it is legal inside a VERIFY
    /// (static) frame where a paymaster staticcalls it to gate APPROVE. A
    /// successful staticcall proves it writes no state.
    function test_verifySpend_is_static() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bool ok,) =
            address(pool).staticcall(abi.encodeWithSelector(ShieldedPool.verifySpend.selector, s));
        assertTrue(ok, "verifySpend must succeed under staticcall (VERIFY-frame legal)");
    }

    /// A proof that does not match its public signals is rejected by verifySpend.
    function test_verifySpend_rejects_mismatched_proof() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.outCm1 = bytes32(uint256(42)); // canonical, but not the proven output
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifySpend(s);
    }

    /// checkKeySet proves the envelope's nonce_keys are exactly the two
    /// nullifiers (distinct, sorted): the binding a VERIFY-frame paymaster
    /// makes once the devnet exposes a nonce_keys selector.
    function test_checkKeySet_binds_keys_to_nullifiers() public {
        ShieldedPool.Spend memory s = _spendOf(".transfer", 1);
        bytes32 lo = s.nf1;
        bytes32 hi = s.nf2;
        if (uint256(lo) > uint256(hi)) { lo = s.nf2; hi = s.nf1; }

        bytes32[] memory good = new bytes32[](2);
        good[0] = lo; good[1] = hi;
        pool.checkKeySet(s, good); // exact set, sorted: accepted (no revert)

        bytes32[] memory unsorted = new bytes32[](2);
        unsorted[0] = hi; unsorted[1] = lo;
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.checkKeySet(s, unsorted);

        bytes32[] memory wrong = new bytes32[](2);
        wrong[0] = lo; wrong[1] = bytes32(uint256(hi) ^ 1);
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.checkKeySet(s, wrong);

        bytes32[] memory tooFew = new bytes32[](1);
        tooFew[0] = lo;
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.checkKeySet(s, tooFew);
    }

    // BN254 scalar field modulus, for the aliasing test below.
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// A nullifier is only canonical in [0, P). The verifier's field check
    /// rejects nf + P as a public signal, and verifySpend's NotCanonical
    /// guard names the failure first: without either, the same proof could
    /// re-verify under a fresh nonce key (nf + P) and double-spend. This
    /// asserts the guard fires.
    function test_verifySpend_rejects_noncanonical_nullifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf1 = bytes32(uint256(s.nf1) + P);
        vm.expectRevert(ShieldedPool.NotCanonical.selector);
        pool.verifySpend(s);
    }

    /// checkKeySet rejects a set whose two nullifiers are equal (nf1 == nf2):
    /// the same-note-through-both-inputs witness, refused by the duplicate-key
    /// clause that is the sole barrier in the VERIFY-frame shape.
    function test_checkKeySet_rejects_duplicate_nullifier() public {
        ShieldedPool.Spend memory s = _spendOf(".attack_same_note", 1); // nf1 == nf2
        bytes32[] memory keys = new bytes32[](2);
        keys[0] = s.nf1; keys[1] = s.nf2;
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.checkKeySet(s, keys);
    }

    /// A root is usable only from its publish slot + 1 (EIP-8272 window lower
    /// bound). A spend referencing it in the same block it was published must
    /// fail, or a same-block reorg could reference a root that never settled.
    function test_root_not_usable_at_publish_slot() public {
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        ShieldedPool.Spend memory s = _spendOf(".transfer", pool.lastRootSlot());
        vm.expectRevert(ShieldedPool.RootNotRecentForPool.selector); // no roll: current == slot
        pool.verifySpend(s);
    }

    /// verifyProofOnly must succeed under STATICCALL for a valid proof EVEN with
    /// a non-recent root (no roll): it omits roots.check, so it reads no storage
    /// and clears the observer's non-sender-SLOAD ban. This is the SLOAD-free
    /// call the ProofPaymaster makes; root recency stays in the SENDER frame.
    function test_verifyProofOnly_is_static_without_root_check() public {
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        ShieldedPool.Spend memory s = _spendOf(".transfer", pool.lastRootSlot());
        // same slot as publish => verifySpend would revert RootNotRecentForPool;
        // verifyProofOnly ignores recency and passes on the valid proof.
        vm.expectRevert(ShieldedPool.RootNotRecentForPool.selector);
        pool.verifySpend(s);
        (bool ok,) =
            address(pool).staticcall(abi.encodeWithSelector(ShieldedPool.verifyProofOnly.selector, s));
        assertTrue(ok, "verifyProofOnly must pass under staticcall regardless of root recency");
    }

    /// Gas split per operation: what a VERIFY frame would spend on the proof
    /// check (verifySpend + the checkKeySet binding) vs what the SENDER/exec
    /// frame spends on state. Run: forge test --mt test_gas_frame_split -vv
    function test_gas_frame_split() public {
        uint256 g;

        // shield: no proof, so nothing runs in a VERIFY frame beyond the
        // sender's self-verify signature; the whole cost is the exec deposit.
        g = gasleft();
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        emit log_named_uint("shield.exec", g - gasleft());
        uint64 slot = pool.lastRootSlot();
        vm.roll(block.number + 1);

        // transfer: VERIFY (verifySpend) + the key-set binding, then total.
        ShieldedPool.Spend memory ts = _spendOf(".transfer", slot);
        g = gasleft();
        pool.verifySpend(ts);
        emit log_named_uint("transfer.verify", g - gasleft());

        bytes32[] memory keys = new bytes32[](2);
        keys[0] = ts.nf1; keys[1] = ts.nf2;
        if (uint256(keys[0]) > uint256(keys[1])) (keys[0], keys[1]) = (ts.nf2, ts.nf1);
        g = gasleft();
        pool.checkKeySet(ts, keys);
        emit log_named_uint("transfer.checkKeySet", g - gasleft());

        vm.prank(POOL_SENDER);
        g = gasleft();
        pool.transfer(ts);
        emit log_named_uint("transfer.total", g - gasleft());
        uint64 slotR2 = pool.lastRootSlot();
        vm.roll(uint256(slotR2) + 2); // past the publish slot so the root is usable

        // withdraw: VERIFY (verifySpend), then total.
        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw", slotR2);
        g = gasleft();
        pool.verifySpend(ws);
        emit log_named_uint("withdraw.verify", g - gasleft());

        vm.prank(POOL_SENDER);
        g = gasleft();
        pool.withdraw(ws, recipient);
        emit log_named_uint("withdraw.total", g - gasleft());
    }

    // minimal assert
    function assertTrue(bool c, string memory m) internal pure {
        require(c, m);
    }
}
