// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "../src/PoseidonBN254.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function expectRevert(bytes4) external;
    function expectCall(address, bytes calldata) external;
    function etch(address, bytes calldata) external;
    function readFile(string calldata) external view returns (string memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseJsonStringArray(string calldata, string calldata) external pure returns (string[] memory);
    function parseBytes32(string calldata) external pure returns (bytes32);
    function parseAddress(string calldata) external pure returns (address);
    function parseUint(string calldata) external pure returns (uint256);
}

/// The attack battery for the JOIN-SPLIT pool, settle-only edition. Every
/// accepted spend carries a real Groth16 proof (wallet/smoke_fixture.json)
/// verified on-chain. The pool keeps no spent set and no root history: _spend
/// binds the transaction envelope (protocol keyed nonces == the proven
/// nullifiers, declared recent-root reference == the proven root) through a
/// stateless probe. Tests deploy a MOCK probe (the frame-tx opcodes do not
/// exist on anvil/Forge) and arm it with the envelope facts a faithful
/// transaction would carry; negatives arm it wrong. The real Yul probe
/// (devnet/EnvelopeProbe.yul) is exercised on the devnet.
contract ShieldedPoolBN254Test {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    ShieldedPool pool;
    MockEnvelopeProbe probe;
    Groth16Verifier verifier;
    string j;

    address constant POOL_SENDER = address(0x5EEDED);
    string constant FIX = "../wallet/smoke_fixture.json";

    event log_named_uint(string key, uint256 val); // decoded by forge at -vv

    function setUp() public {
        vm.roll(1000);
        // NOTE: the probe occupies the deploy slot RecentRoots used to hold,
        // keeping the pool's CREATE address (and so sourceId/domain and the
        // fixture) stable across the settle-only migration.
        probe = new MockEnvelopeProbe();
        probe.setPayer(POOL_SENDER);
        verifier = new Groth16Verifier();
        pool = new ShieldedPool(POOL_SENDER, address(probe), verifier);
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

    function _spendOf(string memory p) internal view returns (ShieldedPool.Spend memory s) {
        s = ShieldedPool.Spend({
            root: _s(string.concat(p, ".root")),
            domain: _s(string.concat(p, ".domain")),
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

    /// Arm the mock probe with the envelope facts the faithful shape carries
    /// for this spend: 3 frames, settling at index 2 targeting the pool,
    /// nonce_keys == sorted {nf1, nf2} at seq 0, one reference (pool source_id,
    /// proven root).
    function _arm(ShieldedPool.Spend memory s) internal {
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool));
    }

    /// Shield Alice's 1.0-ether note so the pool's tree matches the fixture's
    /// transfer root, and return the armed fixture transfer spend.
    function _shieldA() internal returns (ShieldedPool.Spend memory ts) {
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        require(pool.isLeaf(_s(".cm_a")), "shield hashed the wrong commitment");
        require(pool.currentRoot() == _s(".transfer.root"), "pool root after shield != wallet's transfer root");
        ts = _spendOf(".transfer");
        _arm(ts);
    }

    // ---- 1. honest join-split transfer settles ----

    function test_transfer_settles_under_faithful_envelope() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        assertTrue(pool.isLeaf(s.outCm1) && pool.isLeaf(s.outCm2), "both outputs appended");
        assertTrue(pool.feeCredit(POOL_SENDER) == s.fee, "fee credited to submitter");
        assertTrue(pool.currentRoot() == _s(".withdraw.root"), "pool root after transfer != wallet's withdraw root");
    }

    // ---- 2. envelope bindings (the settle-only trust surface) ----

    /// Outside a frame transaction the probe's opcodes halt; the pool must
    /// refuse to settle rather than settle unbound.
    function test_spend_outside_frame_tx_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setHalted();
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.NotFrameNative.selector);
        pool.transfer(s);
    }

    /// Exactly-once: only the faithful [verify, pay, SENDER] grammar settles.
    /// A second settle frame in the same tx would re-credit the fee for one
    /// protocol consumption.
    function test_wrong_frame_shape_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(4, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool)); // four frames
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s);
        probe.set(3, 1, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool)); // wrong index
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s);
    }

    /// The transaction's consumed key set must be exactly the proven
    /// nullifiers: wrong keys, wrong order, wrong count, or nonzero seq all
    /// refuse to settle.
    function test_wrong_key_set_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, hi, lo, 1, pool.sourceId(), s.root, address(pool)); // unsorted
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s);
        probe.set(3, 2, 2, 0, lo, bytes32(uint256(hi) ^ 1), 1, pool.sourceId(), s.root, address(pool)); // wrong key
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s);
        probe.set(3, 2, 1, 0, lo, bytes32(0), 1, pool.sourceId(), s.root, address(pool)); // one key
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s);
        probe.set(3, 2, 2, 1, lo, hi, 1, pool.sourceId(), s.root, address(pool)); // seq != 0
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s);
    }

    /// The proven root must ride as the transaction's declared reference,
    /// under THIS pool's source_id.
    function test_wrong_reference_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 0, bytes32(0), bytes32(0), address(pool)); // no reference
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s);
        probe.set(3, 2, 2, 0, lo, hi, 1, bytes32(uint256(1)), s.root, address(pool)); // foreign source
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), bytes32(uint256(999)), address(pool)); // wrong root
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s);
    }

    /// The settle frame must target the pool directly. If it targets an
    /// intermediary (e.g. a contract POOL_SENDER that re-enters the pool
    /// twice), settleTarget != address(this) and the double-credit is refused.
    /// This is what makes exactly-once independent of POOL_SENDER's shape.
    function test_wrong_settle_target_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, POOL_SENDER); // frame 2 targets sender, not pool
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s);
    }

    /// A foreign root in the SPEND (proof side) mismatches the armed
    /// reference: the settle path catches it before the verifier runs.
    function test_foreign_root_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.root = bytes32(uint256(999));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s);
    }

    // ---- 3. sender pin ----

    function test_cross_sender_spend_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
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
        uint256 before = gasleft();
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.transfer(s);
        assertTrue(before - gasleft() < 1_500_000, "invalid proof consumed unbounded gas");
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

    function test_wrong_domain_reverts_before_verifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.domain = bytes32(uint256(s.domain) ^ 1);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.InvalidDomain.selector);
        pool.transfer(s);
    }

    /// The root is bound by the PROOF, not only by the reference binding:
    /// re-anchor the spend AND its armed reference to a second real root so
    /// the reference check passes and only the verifier stands in the way.
    /// Catches a circuit regression that drops root from the public list.
    function test_referenced_but_unproven_root_reverts_in_verifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        s.root = pool.currentRoot();
        _arm(s); // reference now carries the new root, so that check passes
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

        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        address payable evil = payable(address(0xBEEF));
        ws.ctx = pool.ctxFor(evil);
        _arm(ws);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.withdraw(ws, evil);

        ShieldedPool.Spend memory wp = _spendOf(".withdraw");
        wp.publicAmount = wp.publicAmount + 1;
        _arm(wp);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.withdraw(wp, vm.parseAddress(vm.parseJsonString(j, ".recipient")));
    }

    // ---- 5. operation-shape attacks ----

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
        pool.withdraw(s, address(0xBEEF));
    }

    // ---- 5c. duplicate output is a no-op success, never a revert ----

    function test_duplicate_output_is_noop() public {
        ShieldedPool.Spend memory s = _shieldA();
        // the recipient's opening is known here (fixture), so pre-create the
        // exact output commitment via shield
        pool.shield{value: _u(".transfer.out_value1")}(_s(".transfer.out_inner1"));
        require(pool.isLeaf(s.outCm1), "pre-seeded output leaf");
        uint32 before = pool.nextIndex();
        vm.prank(POOL_SENDER);
        pool.transfer(s); // must not revert
        assertTrue(pool.nextIndex() == before + 1, "only the change note appended");
    }

    // ---- withdraw: full real-proof lifecycle with fees ----

    function test_full_lifecycle_pays_recipient_fees_and_stays_solvent() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(ts);

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.prank(POOL_SENDER);
        pool.withdraw(ws, recipient);

        assertTrue(pool.withdrawalCredit(recipient) == ws.publicAmount, "withdrawal credited");
        assertTrue(pool.feeCredit(POOL_SENDER) == ts.fee + ws.fee, "both fees credited");
        assertTrue(address(pool).balance == _u(".shield_value"), "credits remain escrowed");

        // claims are pushable: a third party (this test contract) pays each
        // party its own recorded credit; no prank / self-call needed.
        uint256 recipientBefore = recipient.balance;
        pool.claimWithdrawal(recipient);
        assertTrue(recipient.balance == recipientBefore + ws.publicAmount, "withdrawal claimed");
        uint256 senderBefore = POOL_SENDER.balance;
        pool.claimFee(payable(POOL_SENDER));
        assertTrue(POOL_SENDER.balance == senderBefore + ts.fee + ws.fee, "fees claimed");
    }

    /// The stranded-fee regression: in the faithful shape the resolved payer
    /// is the paymaster, a passive contract whose only ETH-in path is receive().
    /// A keyed `feeCredit[msg.sender]` claim would strand it. The pushable
    /// claim lets any keeper move the credit into the paymaster's balance,
    /// where it funds future sponsorship.
    function test_anyone_can_push_fee_to_passive_recipient() public {
        PassiveReceiver pm = new PassiveReceiver();
        ShieldedPool.Spend memory s = _shieldA();
        probe.setPayer(address(pm));
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        assertTrue(pool.feeCredit(address(pm)) == s.fee, "fee credited to passive recipient");
        uint256 before = address(pm).balance;
        // a third party (0xF00D), not the recipient, pushes the credit
        vm.prank(address(0xF00D));
        pool.claimFee(payable(address(pm)));
        assertTrue(address(pm).balance == before + s.fee, "credit pushed to passive recipient");
        assertTrue(pool.feeCredit(address(pm)) == 0, "credit cleared after push");
    }

    /// Fee routing is selected by payment approval, not caller calldata. This
    /// models two independently deployed paymasters returned by TXPARAM(0x11).
    function test_distinct_paymasters_receive_only_their_bound_fees() public {
        PassiveReceiver paymasterA = new PassiveReceiver();
        PassiveReceiver paymasterB = new PassiveReceiver();

        ShieldedPool.Spend memory ts = _shieldA();
        probe.setPayer(address(paymasterA));
        vm.prank(POOL_SENDER);
        pool.transfer(ts);

        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        probe.setPayer(address(paymasterB));
        address recipient = vm.parseAddress(vm.parseJsonString(j, ".recipient"));
        vm.prank(POOL_SENDER);
        pool.withdraw(ws, recipient);

        assertTrue(pool.feeCredit(address(paymasterA)) == ts.fee, "paymaster A received only transfer fee");
        assertTrue(pool.feeCredit(address(paymasterB)) == ws.fee, "paymaster B received only withdraw fee");

        uint256 aBefore = address(paymasterA).balance;
        uint256 bBefore = address(paymasterB).balance;
        vm.prank(address(paymasterB));
        pool.claimFee(payable(address(paymasterA)));
        assertTrue(address(paymasterA).balance == aBefore + ts.fee, "A's credit can only be pushed to A");
        assertTrue(address(paymasterB).balance == bBefore, "B cannot redirect A's credit");
        assertTrue(pool.feeCredit(address(paymasterB)) == ws.fee, "B's credit remains separate");
    }

    function test_failed_fee_claim_preserves_credit() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setPayer(address(this));
        vm.prank(POOL_SENDER);
        pool.transfer(s);
        uint256 credit = pool.feeCredit(address(this));
        vm.expectRevert(ShieldedPool.PayoutFailed.selector);
        pool.claimFee(payable(address(this))); // this test contract rejects plain ETH
        assertTrue(pool.feeCredit(address(this)) == credit, "failed claim restored credit");
    }

    function test_zero_resolved_payer_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setPayer(address(0));
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.InvalidPayer.selector);
        pool.transfer(s);
    }

    function test_noncanonical_resolved_payer_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setPayerWord(1 << 160);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.InvalidPayer.selector);
        pool.transfer(s);
    }

    function test_withdraw_wrong_recipient_reverts() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(POOL_SENDER);
        pool.transfer(ts);
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.prank(POOL_SENDER);
        vm.expectRevert(ShieldedPool.CtxDoesNotNameRecipient.selector);
        pool.withdraw(ws, address(0xDEAD));
    }

    // ---- shield rules ----

    function test_constructor_rejects_invalid_immutables() public {
        vm.expectRevert(ShieldedPool.InvalidPoolSender.selector);
        new ShieldedPool(address(0), address(probe), verifier);

        vm.expectRevert(ShieldedPool.InvalidProbe.selector);
        new ShieldedPool(POOL_SENDER, address(1), verifier);

        vm.expectRevert(ShieldedPool.InvalidVerifier.selector);
        new ShieldedPool(POOL_SENDER, address(probe), Groth16Verifier(address(1)));
    }

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

    // ---- EIP-8272 native predeploy (the pool's only root store) ----

    /// Every root publication sends the native predeploy the exact 64-byte
    /// `SALT || root` payload ethrex's native write expects. The expected
    /// root after shielding Alice's note is the fixture's transfer root.
    function test_publish_root_calls_native_predeploy() public {
        vm.expectCall(pool.RECENT_ROOT_PREDEPLOY(), abi.encodePacked(pool.SALT(), _s(".transfer.root")));
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
    }

    /// A reverting predeploy write fails the operation loudly: with no
    /// emulation left, an unpublished root would be unspendable state.
    function test_publish_root_reverts_if_predeploy_reverts() public {
        vm.etch(pool.RECENT_ROOT_PREDEPLOY(), hex"60006000fd"); // PUSH1 0 PUSH1 0 REVERT
        vm.expectRevert(ShieldedPool.RootPublishFailed.selector);
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
    }

    /// The pool's sourceId must equal ethrex's native-write derivation,
    /// keccak256(pad32(source) || salt). Vector computed independently with
    /// the wallet's keccak (Python, eth_hash); pins Solidity's abi.encode
    /// padding against the 64-byte preimage ethrex hashes.
    function test_source_id_matches_ethrex_padded_derivation() public view {
        assertTrue(
            keccak256(abi.encode(address(0xBEEF), bytes32(uint256(7))))
                == 0x93be371628ba90461c1988f904614363a3d7c6cf8ba98ae973416a0339a040f5,
            "abi.encode(source, salt) != keccak256(pad32(source) || salt)"
        );
        assertTrue(
            pool.sourceId() == keccak256(abi.encode(address(pool), pool.SALT())),
            "pool.sourceId not the padded self-derivation"
        );
    }

    // ---- cross-stack fixtures (wallet / Python reference) ----

    function test_ctxFor_matches_wallet() public view {
        assertTrue(pool.ctxFor(address(0xcafebabe)) == _s(".withdraw.ctx"), "ctxFor mismatch vs wallet");
    }

    function test_domain_matches_wallet_fixture() public view {
        assertTrue(pool.domain() == _s(".domain"), "domain mismatch vs wallet");
        assertTrue(
            pool.domainFor(block.chainid, pool.sourceId()) == pool.domain(), "domain is not bound to chain and source"
        );
    }

    function test_tree_root_matches_reference() public view {
        string memory vecs = vm.readFile("../vectors/poseidon_bn254_vectors.json");
        assertTrue(
            uint256(pool.currentRoot()) == vm.parseUint(vm.parseJsonString(vecs, ".tree.root_empty")),
            "empty root mismatch vs reference"
        );
    }

    // ---- verifyProofOnly: the paymaster's prefix check ----

    /// verifyProofOnly must succeed under STATICCALL (VERIFY-frame legal) and
    /// reads no storage, so it clears the observer's non-sender-SLOAD ban.
    function test_verifyProofOnly_is_static() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bool ok,) = address(pool).staticcall(abi.encodeWithSelector(ShieldedPool.verifyProofOnly.selector, s));
        assertTrue(ok, "verifyProofOnly must succeed under staticcall (VERIFY-frame legal)");
    }

    /// A proof that does not match its public signals is rejected.
    function test_verifyProofOnly_rejects_mismatched_proof() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.outCm1 = bytes32(uint256(42)); // canonical, but not the proven output
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    // BN254 scalar field modulus, for the aliasing test below.
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// A nullifier is only canonical in [0, P). The verifier's field check
    /// rejects nf + P as a public signal, and the NotCanonical guard names
    /// the failure first: without either, the same proof could re-verify
    /// under a fresh nonce key (nf + P) and double-spend.
    function test_verifyProofOnly_rejects_noncanonical_nullifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf1 = bytes32(uint256(s.nf1) + P);
        vm.expectRevert(ShieldedPool.NotCanonical.selector);
        pool.verifyProofOnly(s);
    }

    /// Gas split per operation: what the pay VERIFY frame spends on the proof
    /// check vs what the settle-only SENDER frame spends on state.
    /// Run: forge test --mt test_gas_frame_split -vv
    function test_gas_frame_split() public {
        uint256 g;

        g = gasleft();
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        emit log_named_uint("shield.exec", g - gasleft());

        ShieldedPool.Spend memory ts = _spendOf(".transfer");
        _arm(ts);
        g = gasleft();
        pool.verifyProofOnly(ts);
        emit log_named_uint("transfer.verify", g - gasleft());

        vm.prank(POOL_SENDER);
        g = gasleft();
        pool.transfer(ts);
        emit log_named_uint("transfer.total", g - gasleft());

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        g = gasleft();
        pool.verifyProofOnly(ws);
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

/// Configurable stand-in for devnet/EnvelopeProbe.yul: anvil/Forge has no
/// frame-tx opcodes, so tests arm the eleven envelope words a faithful
/// transaction would expose (or halt, emulating a non-frame context).
contract MockEnvelopeProbe {
    bytes blob;
    bool halted;
    uint256 payerWord;

    function setPayer(address payer_) external {
        payerWord = uint256(uint160(payer_));
    }

    function setPayerWord(uint256 payerWord_) external {
        payerWord = payerWord_;
    }

    function set(
        uint256 frames,
        uint256 frameIndex,
        uint256 keyCount,
        uint256 nonceSeq,
        bytes32 k0,
        bytes32 k1,
        uint256 refCount,
        bytes32 refSource,
        bytes32 refRoot,
        address settleTarget
    ) external {
        halted = false;
        blob = abi.encode(frames, frameIndex, keyCount, nonceSeq, k0, k1, refCount, refSource, refRoot, settleTarget);
    }

    function setHalted() external {
        halted = true;
    }

    fallback() external {
        if (halted) revert();
        bytes memory b = bytes.concat(blob, abi.encode(payerWord));
        assembly {
            return(add(b, 32), mload(b))
        }
    }
}

/// A passive ETH sink: accepts plain transfers via receive(), like the faithful
/// paymaster, but has no code path of its own to call the pool's claim.
contract PassiveReceiver {
    receive() external payable {}
}
