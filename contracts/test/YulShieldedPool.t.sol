// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "../src/PoseidonBN254.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MockEnvelopeProbe, PassiveReceiver} from "./ShieldedPool.t.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function expectRevert(bytes4) external;
    function expectCall(address, bytes calldata) external;
    function expectEmit(bool, bool, bool, bool) external;
    function etch(address, bytes calldata) external;
    function readFile(string calldata) external view returns (string memory);
    function parseBytes(string calldata) external pure returns (bytes memory);
    function parseJsonString(string calldata, string calldata) external pure returns (string memory);
    function parseJsonStringArray(string calldata, string calldata) external pure returns (string[] memory);
    function parseBytes32(string calldata) external pure returns (bytes32);
    function parseAddress(string calldata) external pure returns (address);
    function parseUint(string calldata) external pure returns (uint256);
}

/// The Yul pool's external ABI. Struct, selectors, errors, and events are
/// ShieldedPool.sol's exactly; the sender pin differs (the pool IS the
/// sender, so spends require msg.sender == the pool itself).
interface IYulPool {
    function shield(bytes32 inner) external payable returns (uint32);
    function transfer(ShieldedPool.Spend calldata s, address feeRecipient) external;
    function withdraw(ShieldedPool.Spend calldata s, address recipient, address feeRecipient) external;
    function verifyProofOnly(ShieldedPool.Spend calldata s) external view;
    function claimWithdrawal(address payable who) external;
    function claimFee(address payable who) external;
    function currentRoot() external view returns (bytes32);
    function sourceId() external view returns (bytes32);
    function domain() external view returns (bytes32);
    function nextIndex() external view returns (uint32);
    function isLeaf(bytes32) external view returns (bool);
    function withdrawalCredit(address) external view returns (uint256);
    function feeCredit(address) external view returns (uint256);
    function filledSubtrees(uint256) external view returns (bytes32);
    function ctxFor(address) external pure returns (bytes32);
    function domainFor(uint256, bytes32) external pure returns (bytes32);
    function probe() external view returns (address);
    function verifier() external view returns (address);
    function DEPTH() external view returns (uint32);
}

/// External-call shims for the internal PoseidonBN254 library, etched at
/// fixed addresses so the Yul pool's external hash2/hash3 calls compute
/// byte-exactly what the Solidity pool computed internally.
contract PoseidonT3Shim {
    function hash2(uint256 x0, uint256 x1) external pure returns (uint256) {
        return PoseidonBN254.hash2(x0, x1);
    }
}

contract PoseidonT4Shim {
    function hash3(uint256 x0, uint256 x1, uint256 x2) external pure returns (uint256) {
        return PoseidonBN254.hash3(x0, x1, x2);
    }
}

/// Payout recipient that tries to re-enter both settlement entrypoints while
/// the pool is paying a pull credit. The nested calls originate from this
/// contract, not from the pool, even though the outer payout CALL was issued
/// by the pool. Both must therefore fail the pool-as-sender caller check.
contract ReentrantSettlementProbe {
    address public target;
    bytes public transferCall;
    bytes public withdrawCall;
    bool public attempted;
    bool public transferSucceeded;
    bool public withdrawSucceeded;
    bytes4 public transferError;
    bytes4 public withdrawError;

    function arm(address target_, bytes calldata transferCall_, bytes calldata withdrawCall_) external {
        target = target_;
        transferCall = transferCall_;
        withdrawCall = withdrawCall_;
    }

    receive() external payable {
        attempted = true;
        bytes memory ret;
        (transferSucceeded, ret) = target.call(transferCall);
        transferError = _selector(ret);
        (withdrawSucceeded, ret) = target.call(withdrawCall);
        withdrawError = _selector(ret);
    }

    function _selector(bytes memory ret) private pure returns (bytes4 out) {
        if (ret.length < 4) return bytes4(0);
        assembly {
            out := mload(add(ret, 32))
        }
    }
}

/// The ShieldedPool.t.sol attack battery, ported to the Yul pool-as-sender
/// (devnet/ShieldedPool.yul). Every behavioral test is the same; the
/// adaptations are exactly the design deltas:
///
///   - the pool is deployed from devnet/build/shielded_pool_init.hex (bare
///     initcode + the four-word immutable tail), at the SAME CREATE slot the
///     Solidity pool occupied (deployer + third nonce), so sourceId/domain
///     and the wallet fixture bind unchanged. setUp asserts this.
///   - the sender pin is the pool itself: spends prank address(pool), and
///     the cross-sender test expects NotPoolSender for anyone else.
///   - the constructor-argument validation test is replaced by an
///     immutable-tail round-trip test (raw initcode has no constructor args).
///
/// Regenerate the initcode artifact after any ShieldedPool.yul change:
///   cd ../devnet && python3 yul_pool.py --artifact
contract YulShieldedPoolTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    IYulPool pool;
    MockEnvelopeProbe probe;
    Groth16Verifier verifier;
    string j;

    // the fee-recipient argument of ported spends (the old POOL_SENDER
    // constant, kept as a plain address so the fee-credit assertions port
    // unchanged); the sender pin itself is address(pool) now.
    address constant SUBMITTER = address(0x5EEDED);
    address constant T3_SHIM = address(0xA3);
    address constant T4_SHIM = address(0xA4);
    address constant RECENT_ROOT_PREDEPLOY = address(0x8272);
    bytes32 constant SALT = bytes32(0);
    string constant FIX = "../wallet/smoke_fixture.json";
    string constant INIT_HEX = "../devnet/build/shielded_pool_init.hex";

    event LeafAppended(bytes32 indexed cm, uint32 index, bytes32 newRoot, uint64 slot);
    event NoteSpent(bytes32 indexed nf);
    event Withdrawn(address indexed recipient, uint256 amount);
    event FeePaid(address indexed to, uint256 amount);
    event WithdrawalCredited(address indexed recipient, uint256 amount);
    event FeeCredited(address indexed recipient, uint256 amount);
    event log_named_uint(string key, uint256 val); // decoded by forge at -vv

    function setUp() public {
        vm.roll(1000);
        // Same creates, same order, same deployer as ShieldedPool.t.sol's
        // setUp, so the pool lands at the CREATE address the wallet fixture's
        // domain was generated for.
        probe = new MockEnvelopeProbe();
        verifier = new Groth16Verifier();
        vm.etch(T3_SHIM, type(PoseidonT3Shim).runtimeCode);
        vm.etch(T4_SHIM, type(PoseidonT4Shim).runtimeCode);
        bytes memory initcode = bytes.concat(
            vm.parseBytes(vm.readFile(INIT_HEX)), abi.encode(T3_SHIM, T4_SHIM, address(verifier), address(probe))
        );
        address deployed;
        assembly {
            deployed := create(0, add(initcode, 32), mload(initcode))
        }
        require(deployed != address(0), "yul pool deploy failed");
        pool = IYulPool(deployed);
        vm.deal(address(this), 100 ether);
        j = vm.readFile(FIX);
        // fail fast if the CREATE-slot assumption ever breaks: every proof in
        // the fixture binds this domain
        require(pool.domain() == _s(".domain"), "pool address drifted: fixture domain no longer binds");
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
        vm.prank(address(pool));
        pool.transfer(s, SUBMITTER);
        assertTrue(pool.isLeaf(s.outCm1) && pool.isLeaf(s.outCm2), "both outputs appended");
        assertTrue(pool.feeCredit(SUBMITTER) == s.fee, "fee credited to submitter");
        assertTrue(pool.currentRoot() == _s(".withdraw.root"), "pool root after transfer != wallet's withdraw root");
    }

    // ---- 2. envelope bindings (the settle-only trust surface) ----

    /// Outside a frame transaction the probe's opcodes halt; the pool must
    /// refuse to settle rather than settle unbound.
    function test_spend_outside_frame_tx_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setHalted();
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.NotFrameNative.selector);
        pool.transfer(s, SUBMITTER);
    }

    /// Exactly-once: only the faithful [verify, pay, SENDER] grammar settles.
    function test_wrong_frame_shape_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(4, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool)); // four frames
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s, SUBMITTER);
        probe.set(3, 1, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool)); // wrong index
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s, SUBMITTER);
    }

    /// The transaction's consumed key set must be exactly the proven
    /// nullifiers: wrong keys, wrong order, wrong count, or nonzero seq all
    /// refuse to settle.
    function test_wrong_key_set_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, hi, lo, 1, pool.sourceId(), s.root, address(pool)); // unsorted
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s, SUBMITTER);
        probe.set(3, 2, 2, 0, lo, bytes32(uint256(hi) ^ 1), 1, pool.sourceId(), s.root, address(pool)); // wrong key
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s, SUBMITTER);
        probe.set(3, 2, 1, 0, lo, bytes32(0), 1, pool.sourceId(), s.root, address(pool)); // one key
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s, SUBMITTER);
        probe.set(3, 2, 2, 1, lo, hi, 1, pool.sourceId(), s.root, address(pool)); // seq != 0
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s, SUBMITTER);
    }

    /// The proven root must ride as the transaction's declared reference,
    /// under THIS pool's source_id.
    function test_wrong_reference_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 0, bytes32(0), bytes32(0), address(pool)); // no reference
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s, SUBMITTER);
        probe.set(3, 2, 2, 0, lo, hi, 1, bytes32(uint256(1)), s.root, address(pool)); // foreign source
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s, SUBMITTER);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), bytes32(uint256(999)), address(pool)); // wrong root
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s, SUBMITTER);
    }

    /// The settle frame must target the pool directly; an intermediary that
    /// re-enters cannot double-credit against one protocol consumption.
    function test_wrong_settle_target_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, SUBMITTER); // frame 2 targets an intermediary
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s, SUBMITTER);
    }

    /// A foreign root in the SPEND (proof side) mismatches the armed
    /// reference: the settle path catches it before the verifier runs.
    function test_foreign_root_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.root = bytes32(uint256(999));
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s, SUBMITTER);
    }

    // ---- 3. sender pin (the pool IS the sender) ----

    function test_cross_sender_spend_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(address(0xEEEE));
        vm.expectRevert(ShieldedPool.NotPoolSender.selector);
        pool.transfer(s, SUBMITTER);
    }

    /// The old external POOL_SENDER is just another stranger now.
    function test_old_pool_sender_address_cannot_spend() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(SUBMITTER);
        vm.expectRevert(ShieldedPool.NotPoolSender.selector);
        pool.transfer(s, SUBMITTER);
    }

    // ---- 4. proof attacks ----

    function test_zero_nullifier_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf2 = bytes32(0);
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.ZeroNullifier.selector);
        pool.transfer(s, SUBMITTER);
    }

    function test_corrupted_proof_rejected_at_authentication() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.pA[0] = addmod(s.pA[0], 1, 21888242871839275222246405745257275088696311157297823662689037894645226208583);
        uint256 before = gasleft();
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
        assertTrue(before - gasleft() < 1_500_000, "invalid proof consumed unbounded gas");
    }

    /// A valid proof cannot have its amounts re-priced: fee and publicAmount
    /// are public signals the proof binds, so tampering kills the proof.
    function test_tampered_fee_rejected_at_authentication() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.fee = s.fee + 1;
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    function test_tampered_outputs_rejected_at_authentication() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.outCm1 = bytes32(uint256(12345));
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    function test_wrong_domain_reverts_before_verifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.domain = bytes32(uint256(s.domain) ^ 1);
        vm.expectRevert(ShieldedPool.InvalidDomain.selector);
        pool.verifyProofOnly(s);
    }

    /// The root is bound by the PROOF, not only by the reference binding.
    function test_referenced_but_unproven_root_rejected_at_authentication() public {
        ShieldedPool.Spend memory s = _shieldA();
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        s.root = pool.currentRoot();
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    /// ctx and publicAmount are bound by the PROOF, not only by the shape
    /// checks.
    function test_rebound_ctx_and_repriced_amount_rejected_at_authentication() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts, SUBMITTER);

        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        address payable evil = payable(address(0xBEEF));
        ws.ctx = pool.ctxFor(evil);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(ws);

        ShieldedPool.Spend memory wp = _spendOf(".withdraw");
        wp.publicAmount = wp.publicAmount + 1;
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(wp);
    }

    // ---- 5. operation-shape attacks ----

    function test_withdraw_shaped_spend_rejected_by_transfer() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.publicAmount = 1; // nonzero publicAmount is not a transfer
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.TransferShape.selector);
        pool.transfer(s, SUBMITTER);
    }

    function test_transfer_shaped_spend_rejected_by_withdraw() public {
        ShieldedPool.Spend memory s = _shieldA(); // publicAmount == 0, ctx == 0
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.WithdrawShape.selector);
        pool.withdraw(s, address(0xBEEF), SUBMITTER);
    }

    // ---- 5c. duplicate output is a no-op success, never a revert ----

    function test_duplicate_output_is_noop() public {
        ShieldedPool.Spend memory s = _shieldA();
        pool.shield{value: _u(".transfer.out_value1")}(_s(".transfer.out_inner1"));
        require(pool.isLeaf(s.outCm1), "pre-seeded output leaf");
        uint32 before = pool.nextIndex();
        vm.prank(address(pool));
        pool.transfer(s, SUBMITTER); // must not revert
        assertTrue(pool.nextIndex() == before + 1, "only the change note appended");
    }

    // ---- withdraw: full real-proof lifecycle with fees ----

    function test_full_lifecycle_pays_recipient_fees_and_stays_solvent() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts, SUBMITTER);

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.prank(address(pool));
        pool.withdraw(ws, recipient, SUBMITTER);

        assertTrue(pool.withdrawalCredit(recipient) == ws.publicAmount, "withdrawal credited");
        assertTrue(pool.feeCredit(SUBMITTER) == ts.fee + ws.fee, "both fees credited");
        assertTrue(address(pool).balance == _u(".shield_value"), "credits remain escrowed");

        uint256 recipientBefore = recipient.balance;
        pool.claimWithdrawal(recipient);
        assertTrue(recipient.balance == recipientBefore + ws.publicAmount, "withdrawal claimed");
        uint256 senderBefore = SUBMITTER.balance;
        pool.claimFee(payable(SUBMITTER));
        assertTrue(SUBMITTER.balance == senderBefore + ts.fee + ws.fee, "fees claimed");
    }

    /// The stranded-fee regression: pushable claims let a passive contract
    /// recipient (the faithful-shape paymaster) actually collect its fee.
    function test_anyone_can_push_fee_to_passive_recipient() public {
        PassiveReceiver pm = new PassiveReceiver();
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(address(pool));
        pool.transfer(s, address(pm)); // fee recipient is the passive contract
        assertTrue(pool.feeCredit(address(pm)) == s.fee, "fee credited to passive recipient");
        uint256 before = address(pm).balance;
        vm.prank(address(0xF00D));
        pool.claimFee(payable(address(pm)));
        assertTrue(address(pm).balance == before + s.fee, "credit pushed to passive recipient");
        assertTrue(pool.feeCredit(address(pm)) == 0, "credit cleared after push");
    }

    /// A payout CALL gives arbitrary recipient code control while the pool is
    /// on the stack, but a callback into the pool has caller == recipient, not
    /// caller == pool. Even ABI-valid transfer and withdraw payloads therefore
    /// stop at NotPoolSender before reading the probe or verifying a proof.
    function test_payout_reentrancy_cannot_enter_settlement_as_pool() public {
        ReentrantSettlementProbe recipient = new ReentrantSettlementProbe();
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts, address(recipient));

        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        address withdrawalRecipient = vm.parseAddress(vm.parseJsonString(j, ".recipient"));
        recipient.arm(
            address(pool),
            abi.encodeWithSelector(IYulPool.transfer.selector, ts, address(recipient)),
            abi.encodeWithSelector(IYulPool.withdraw.selector, ws, withdrawalRecipient, address(recipient))
        );

        pool.claimFee(payable(address(recipient)));

        assertTrue(recipient.attempted(), "recipient callback did not run");
        assertTrue(!recipient.transferSucceeded(), "reentrant transfer entered settlement");
        assertTrue(!recipient.withdrawSucceeded(), "reentrant withdraw entered settlement");
        assertTrue(recipient.transferError() == ShieldedPool.NotPoolSender.selector, "wrong transfer rejection");
        assertTrue(recipient.withdrawError() == ShieldedPool.NotPoolSender.selector, "wrong withdraw rejection");
        assertTrue(address(recipient).balance == ts.fee, "recipient did not retain the paid credit");
        assertTrue(pool.feeCredit(address(recipient)) == 0, "paid credit was not cleared");
    }

    /// Fee routing is selected per spend, not pinned in the pool.
    function test_distinct_paymasters_receive_only_their_bound_fees() public {
        PassiveReceiver paymasterA = new PassiveReceiver();
        PassiveReceiver paymasterB = new PassiveReceiver();

        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts, address(paymasterA));

        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        address recipient = vm.parseAddress(vm.parseJsonString(j, ".recipient"));
        vm.prank(address(pool));
        pool.withdraw(ws, recipient, address(paymasterB));

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
        vm.prank(address(pool));
        pool.transfer(s, address(this));
        uint256 credit = pool.feeCredit(address(this));
        vm.expectRevert(ShieldedPool.PayoutFailed.selector);
        pool.claimFee(payable(address(this))); // this test contract rejects plain ETH
        assertTrue(pool.feeCredit(address(this)) == credit, "failed claim restored credit");
    }

    function test_withdraw_wrong_recipient_reverts() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts, SUBMITTER);
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.CtxDoesNotNameRecipient.selector);
        pool.withdraw(ws, address(0xDEAD), SUBMITTER);
    }

    // ---- deploy-time state (replaces the constructor-argument tests: raw
    // initcode has no constructor args, the immutable tail is the contract) --

    function test_immutable_tail_round_trips() public view {
        assertTrue(pool.probe() == address(probe), "probe immutable");
        assertTrue(pool.verifier() == address(verifier), "verifier immutable");
        assertTrue(pool.DEPTH() == 20, "depth");
        assertTrue(pool.nextIndex() == 0, "fresh tree");
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

    // ---- events (the wallet reconstructs the tree from LeafAppended) ----

    function test_shield_emits_leaf_appended() public {
        vm.expectEmit(true, false, false, true);
        emit LeafAppended(_s(".cm_a"), 0, _s(".transfer.root"), uint64(block.number));
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
    }

    /// The full spend emission sequence, matching ShieldedPool.sol's order:
    /// NoteSpent for nf1 then nf2 (as proven, not sorted), LeafAppended for
    /// each new output under the SAME post-insertion root, then FeeCredited.
    function test_transfer_emits_full_sequence_in_order() public {
        ShieldedPool.Spend memory s = _shieldA();
        bytes32 rootAfter = _s(".withdraw.root"); // fixture: pool root after the transfer
        vm.expectEmit(true, false, false, true);
        emit NoteSpent(s.nf1);
        vm.expectEmit(true, false, false, true);
        emit NoteSpent(s.nf2);
        vm.expectEmit(true, false, false, true);
        emit LeafAppended(s.outCm1, 1, rootAfter, uint64(block.number));
        vm.expectEmit(true, false, false, true);
        emit LeafAppended(s.outCm2, 2, rootAfter, uint64(block.number));
        vm.expectEmit(true, false, false, true);
        emit FeeCredited(SUBMITTER, s.fee);
        vm.prank(address(pool));
        pool.transfer(s, SUBMITTER);
    }

    function test_withdraw_and_claims_emit() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts, SUBMITTER);

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.expectEmit(true, false, false, true);
        emit FeeCredited(SUBMITTER, ws.fee);
        vm.expectEmit(true, false, false, true);
        emit WithdrawalCredited(recipient, ws.publicAmount);
        vm.prank(address(pool));
        pool.withdraw(ws, recipient, SUBMITTER);

        vm.expectEmit(true, false, false, true);
        emit Withdrawn(recipient, ws.publicAmount);
        pool.claimWithdrawal(recipient);
        vm.expectEmit(true, false, false, true);
        emit FeePaid(SUBMITTER, ts.fee + ws.fee);
        pool.claimFee(payable(SUBMITTER));
    }

    // ---- EIP-8272 native predeploy (the pool's only root store) ----

    function test_publish_root_calls_native_predeploy() public {
        vm.expectCall(RECENT_ROOT_PREDEPLOY, abi.encodePacked(SALT, _s(".transfer.root")));
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
    }

    function test_publish_root_reverts_if_predeploy_reverts() public {
        vm.etch(RECENT_ROOT_PREDEPLOY, hex"60006000fd"); // PUSH1 0 PUSH1 0 REVERT
        vm.expectRevert(ShieldedPool.RootPublishFailed.selector);
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
    }

    function test_source_id_matches_ethrex_padded_derivation() public view {
        assertTrue(
            pool.sourceId() == keccak256(abi.encode(address(pool), SALT)),
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

    function test_verifyProofOnly_is_static() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bool ok,) = address(pool).staticcall(abi.encodeWithSelector(IYulPool.verifyProofOnly.selector, s));
        assertTrue(ok, "verifyProofOnly must succeed under staticcall (VERIFY-frame legal)");
    }

    function test_verifyProofOnly_rejects_mismatched_proof() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.outCm1 = bytes32(uint256(42)); // canonical, but not the proven output
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    // BN254 scalar field modulus, for the aliasing test below.
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function test_verifyProofOnly_rejects_noncanonical_nullifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf1 = bytes32(uint256(s.nf1) + P);
        vm.expectRevert(ShieldedPool.NotCanonical.selector);
        pool.verifyProofOnly(s);
    }

    /// Gas split per operation. Run: forge test --mt test_gas_frame_split -vv
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

        vm.prank(address(pool));
        g = gasleft();
        pool.transfer(ts, SUBMITTER);
        emit log_named_uint("transfer.total", g - gasleft());

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        g = gasleft();
        pool.verifyProofOnly(ws);
        emit log_named_uint("withdraw.verify", g - gasleft());

        vm.prank(address(pool));
        g = gasleft();
        pool.withdraw(ws, recipient, SUBMITTER);
        emit log_named_uint("withdraw.total", g - gasleft());
    }

    // minimal assert
    function assertTrue(bool c, string memory m) internal pure {
        require(c, m);
    }
}
