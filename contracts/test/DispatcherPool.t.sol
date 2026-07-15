// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "../src/PoseidonBN254.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {ShieldedPoolLogic} from "../src/ShieldedPoolLogic.sol";
import {MockEnvelopeProbe, PassiveReceiver} from "./ShieldedPool.t.sol";
import {PoseidonT3Shim, PoseidonT4Shim} from "./YulShieldedPool.t.sol";

interface Vm {
    function prank(address) external;
    function deal(address, uint256) external;
    function roll(uint256) external;
    function load(address, bytes32) external view returns (bytes32);
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

/// The dispatcher's external ABI is ShieldedPoolLogic's (routed through the
/// proxy). Same selectors/errors/events as ShieldedPool.sol.
interface IPool {
    function shield(bytes32 inner) external payable returns (uint32);
    function transfer(ShieldedPool.Spend calldata s) external;
    function withdraw(ShieldedPool.Spend calldata s, address recipient) external;
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
    function DEPTH() external view returns (uint32);
}

/// Re-enters both settlement entrypoints while the pool pays it a pull credit.
/// The callbacks originate from this contract, so caller != pool; both must
/// fail the pool-as-sender pin.
contract ReentrantProbe {
    address public target;
    bytes public transferCall;
    bytes public withdrawCall;
    bytes4 public transferError;
    bytes4 public withdrawError;

    function arm(address t, bytes calldata tc, bytes calldata wc) external {
        target = t;
        transferCall = tc;
        withdrawCall = wc;
    }

    receive() external payable {
        bytes memory ret;
        bool ok;
        (ok, ret) = target.call(transferCall);
        require(!ok, "transfer re-entry settled");
        transferError = _sel(ret);
        (ok, ret) = target.call(withdrawCall);
        require(!ok, "withdraw re-entry settled");
        withdrawError = _sel(ret);
    }

    function _sel(bytes memory ret) private pure returns (bytes4 out) {
        if (ret.length < 4) return bytes4(0);
        assembly {
            out := mload(add(ret, 32))
        }
    }
}

/// The pool-as-sender battery against the DISPATCHER + Solidity logic
/// (devnet/ShieldedPoolDispatcher.yul delegatecalling
/// contracts/src/ShieldedPoolLogic.sol), the production-preferred split. The
/// dispatcher is deployed from its compiled initcode with the logic address
/// appended, so the settlement path is compiled Solidity reached through the
/// proxy. The frame-0 VERIFY path uses opcodes Forge cannot execute and is
/// validated live.
///
/// Regenerate the dispatcher initcode artifact and fixture after any change:
///   cd ../devnet && python3 dispatcher.py --artifact
///   (fixture: gen_smoke.py --source-id=<dispatcher sourceId>, see test_identity)
contract DispatcherPoolTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    IPool pool; // the dispatcher (the pool)
    ShieldedPoolLogic logic;
    MockEnvelopeProbe probe;
    Groth16Verifier verifier;
    string j;

    address constant SUBMITTER = address(0x5EEDED);
    address constant T3_SHIM = address(0xA3);
    address constant T4_SHIM = address(0xA4);
    address constant RECENT_ROOT_PREDEPLOY = address(0x8272);
    bytes32 constant SALT = bytes32(0);
    string constant FIX = "../wallet/dispatcher_smoke_fixture.json";
    string constant DISPATCHER_INIT_HEX = "../devnet/build/shielded_pool_dispatcher_init.hex";
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    event LeafAppended(bytes32 indexed cm, uint32 index, bytes32 newRoot, uint64 slot);
    event NoteSpent(bytes32 indexed nf);
    event FeeCredited(address indexed recipient, uint256 amount);
    event WithdrawalCredited(address indexed recipient, uint256 amount);
    event log_named_bytes32(string key, bytes32 val);
    event log_named_address(string key, address val);

    function _deploy() internal {
        probe = new MockEnvelopeProbe(); // nonce 1
        probe.setPayer(SUBMITTER);
        verifier = new Groth16Verifier(); // nonce 2
        vm.etch(T3_SHIM, type(PoseidonT3Shim).runtimeCode);
        vm.etch(T4_SHIM, type(PoseidonT4Shim).runtimeCode);
        // PoseidonBN254 links PoseidonT3/T4 by library address; the etched
        // shims stand in for the deployed libraries the logic calls.
        logic = new ShieldedPoolLogic(address(probe), verifier); // nonce 3
        bytes memory initcode = bytes.concat(
            vm.parseBytes(vm.readFile(DISPATCHER_INIT_HEX)), abi.encode(address(logic), address(verifier))
        );
        address d;
        assembly {
            d := create(0, add(initcode, 32), mload(initcode)) // nonce 4
        }
        require(d != address(0), "dispatcher deploy failed");
        pool = IPool(d);
    }

    function setUp() public {
        vm.roll(1000);
        _deploy();
        vm.deal(address(this), 100 ether);
        j = vm.readFile(FIX);
        require(pool.domain() == _s(".domain"), "pool address drifted: dispatcher fixture no longer binds");
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

    function _arm(ShieldedPool.Spend memory s) internal {
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool));
    }

    function _armSelfPay(ShieldedPool.Spend memory s) internal {
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.setPayer(address(pool));
        probe.set(2, 1, 2, 0, lo, hi, 1, pool.sourceId(), s.root, address(pool));
    }

    function _shieldA() internal returns (ShieldedPool.Spend memory ts) {
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        require(pool.isLeaf(_s(".cm_a")), "shield hashed the wrong commitment");
        require(pool.currentRoot() == _s(".transfer.root"), "pool root after shield != wallet's transfer root");
        ts = _spendOf(".transfer");
        _arm(ts);
    }

    // ---- delegatecall context: the dispatcher is the pool, the logic is not ----

    /// The dispatcher's identity derives from ITS address (address(this) under
    /// delegatecall), not the logic's own deploy address. This is the property
    /// that made sourceId/domain runtime functions rather than immutables.
    function test_identity_derives_from_pool_not_logic() public view {
        assertTrue(pool.sourceId() == keccak256(abi.encode(address(pool), SALT)), "pool sourceId is self-derived");
        assertTrue(logic.sourceId() != pool.sourceId(), "logic's own sourceId differs from the pool's");
        assertTrue(pool.domain() == pool.domainFor(block.chainid, pool.sourceId()), "domain bound to chain and source");
        assertTrue(pool.DEPTH() == 20, "DEPTH via proxy");
    }

    /// Storage lives at the dispatcher. After a shield, the pool's slots 21
    /// (nextIndex) and 22 (currentRoot) hold the tree state, and the logic
    /// contract's own storage is untouched. This is the storage-layout contract
    /// between the Yul dispatcher and the Solidity implementation.
    function test_storage_layout_contract() public {
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
        // slot 21: nextIndex (uint32, low bytes); slot 22: currentRoot.
        assertTrue(uint256(vm.load(address(pool), bytes32(uint256(21)))) == 1, "nextIndex at slot 21");
        assertTrue(vm.load(address(pool), bytes32(uint256(22))) == _s(".transfer.root"), "currentRoot at slot 22");
        // isLeaf mapping at base slot 23: keccak(cm . 23) == 1.
        bytes32 leafSlot = keccak256(abi.encode(_s(".cm_a"), uint256(23)));
        assertTrue(uint256(vm.load(address(pool), leafSlot)) == 1, "isLeaf at mapping base 23");
        // the logic contract itself saw none of this write.
        assertTrue(vm.load(address(logic), bytes32(uint256(21))) == 0, "logic nextIndex untouched");
    }

    // ---- honest settlement through the proxy ----

    function test_transfer_settles_under_faithful_envelope() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(address(pool));
        pool.transfer(s);
        assertTrue(pool.isLeaf(s.outCm1) && pool.isLeaf(s.outCm2), "both outputs appended");
        assertTrue(pool.feeCredit(SUBMITTER) == s.fee, "fee credited");
        assertTrue(pool.currentRoot() == _s(".withdraw.root"), "root advanced to wallet's withdraw root");
    }

    function test_self_paying_two_frame_shape_settles_without_fee_credit() public {
        ShieldedPool.Spend memory s = _shieldA();
        _armSelfPay(s);
        vm.prank(address(pool));
        pool.transfer(s);
        assertTrue(pool.isLeaf(s.outCm1) && pool.isLeaf(s.outCm2), "self-pay outputs appended");
        assertTrue(pool.feeCredit(address(pool)) == 0, "self-pay fee retained, not credited");
    }

    function test_transfer_emits_full_sequence_in_order() public {
        ShieldedPool.Spend memory s = _shieldA();
        bytes32 rootAfter = _s(".withdraw.root");
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
        pool.transfer(s);
    }

    function test_full_lifecycle_pays_recipient_fees_and_stays_solvent() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts);

        address payable recipient = payable(vm.parseAddress(vm.parseJsonString(j, ".recipient")));
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.prank(address(pool));
        pool.withdraw(ws, recipient);

        assertTrue(pool.withdrawalCredit(recipient) == ws.publicAmount, "withdrawal credited");
        assertTrue(pool.feeCredit(SUBMITTER) == ts.fee + ws.fee, "both fees credited");
        assertTrue(address(pool).balance == _u(".shield_value"), "credits escrowed at the pool");

        uint256 rb = recipient.balance;
        pool.claimWithdrawal(recipient);
        assertTrue(recipient.balance == rb + ws.publicAmount, "withdrawal claimed from pool balance");
        uint256 sb = SUBMITTER.balance;
        pool.claimFee(payable(SUBMITTER));
        assertTrue(SUBMITTER.balance == sb + ts.fee + ws.fee, "fees claimed");
    }

    // ---- pin: the pool is its own sender ----

    function test_cross_sender_spend_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(address(0xEEEE));
        vm.expectRevert(ShieldedPool.NotPoolSender.selector);
        pool.transfer(s);
    }

    /// A payout CALL gives the recipient control while the pool is on the
    /// stack, but a re-entry has caller == recipient, not caller == pool; even
    /// ABI-valid settlement payloads stop at NotPoolSender.
    function test_payout_reentrancy_cannot_settle_as_pool() public {
        ReentrantProbe r = new ReentrantProbe();
        ShieldedPool.Spend memory ts = _shieldA();
        ShieldedPool.Spend memory fakeT = _spendOf(".transfer");
        ShieldedPool.Spend memory fakeW = _spendOf(".withdraw");
        // withdraw re-entry names the fixture's real recipient so it clears the
        // ctx check and reaches the sender pin (the property under test), rather
        // than short-circuiting on CtxDoesNotNameRecipient.
        address wRecipient = vm.parseAddress(vm.parseJsonString(j, ".recipient"));
        r.arm(
            address(pool),
            abi.encodeWithSelector(IPool.transfer.selector, fakeT),
            abi.encodeWithSelector(IPool.withdraw.selector, fakeW, wRecipient)
        );
        probe.setPayer(address(r));
        vm.prank(address(pool));
        pool.transfer(ts);
        pool.claimFee(payable(address(r)));
        assertTrue(r.transferError() == ShieldedPool.NotPoolSender.selector, "transfer re-entry pinned");
        assertTrue(r.withdrawError() == ShieldedPool.NotPoolSender.selector, "withdraw re-entry pinned");
    }

    // ---- envelope bindings (settlement side, via the mock probe) ----

    function test_spend_outside_frame_tx_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setHalted();
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.NotFrameNative.selector);
        pool.transfer(s);
    }

    function test_wrong_key_set_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, hi, lo, 1, pool.sourceId(), s.root, address(pool));
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.KeySetMismatch.selector);
        pool.transfer(s);
    }

    function test_wrong_reference_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), bytes32(uint256(999)), address(pool));
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.RootNotBoundToReference.selector);
        pool.transfer(s);
    }

    function test_wrong_settle_target_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bytes32 lo, bytes32 hi) = uint256(s.nf1) < uint256(s.nf2) ? (s.nf1, s.nf2) : (s.nf2, s.nf1);
        probe.set(3, 2, 2, 0, lo, hi, 1, pool.sourceId(), s.root, SUBMITTER);
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.NotFaithfulShape.selector);
        pool.transfer(s);
    }

    function test_zero_resolved_payer_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setPayer(address(0));
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.InvalidPayer.selector);
        pool.transfer(s);
    }

    function test_noncanonical_resolved_payer_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        probe.setPayerWord(1 << 160);
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.InvalidPayer.selector);
        pool.transfer(s);
    }

    // ---- proof attacks: rejected at the verifyProofOnly authentication
    // boundary (settlement no longer re-verifies) ----

    function test_zero_nullifier_reverts() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf2 = bytes32(0);
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.ZeroNullifier.selector);
        pool.transfer(s);
    }

    function test_corrupted_proof_rejected_at_authentication() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.pA[0] = addmod(s.pA[0], 1, 21888242871839275222246405745257275088696311157297823662689037894645226208583);
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    function test_tampered_fee_rejected_at_authentication() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.fee = s.fee + 1;
        vm.expectRevert(ShieldedPool.ProofInvalid.selector);
        pool.verifyProofOnly(s);
    }

    function test_wrong_domain_reverts_before_verifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.domain = bytes32(uint256(s.domain) ^ 1);
        vm.expectRevert(ShieldedPool.InvalidDomain.selector);
        pool.verifyProofOnly(s);
    }

    function test_verifyProofOnly_is_static() public {
        ShieldedPool.Spend memory s = _shieldA();
        (bool ok,) = address(pool).staticcall(abi.encodeWithSelector(IPool.verifyProofOnly.selector, s));
        assertTrue(ok, "verifyProofOnly must succeed under staticcall through the proxy");
    }

    function test_verifyProofOnly_rejects_noncanonical_nullifier() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.nf1 = bytes32(uint256(s.nf1) + P);
        vm.expectRevert(ShieldedPool.NotCanonical.selector);
        pool.verifyProofOnly(s);
    }

    // ---- shape ----

    function test_withdraw_shaped_spend_rejected_by_transfer() public {
        ShieldedPool.Spend memory s = _shieldA();
        s.publicAmount = 1;
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.TransferShape.selector);
        pool.transfer(s);
    }

    function test_transfer_shaped_spend_rejected_by_withdraw() public {
        ShieldedPool.Spend memory s = _shieldA();
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.WithdrawShape.selector);
        pool.withdraw(s, address(0xBEEF));
    }

    function test_withdraw_wrong_recipient_reverts() public {
        ShieldedPool.Spend memory ts = _shieldA();
        vm.prank(address(pool));
        pool.transfer(ts);
        ShieldedPool.Spend memory ws = _spendOf(".withdraw");
        _arm(ws);
        vm.prank(address(pool));
        vm.expectRevert(ShieldedPool.CtxDoesNotNameRecipient.selector);
        pool.withdraw(ws, address(0xDEAD));
    }

    // ---- shield rules & duplicate-output no-op ----

    function test_shield_zero_value_reverts() public {
        vm.expectRevert(ShieldedPool.ZeroValueShield.selector);
        pool.shield{value: 0}(bytes32(uint256(1)));
    }

    function test_shield_duplicate_commitment_reverts() public {
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        vm.expectRevert(ShieldedPool.DuplicateCommitment.selector);
        pool.shield{value: 1 ether}(bytes32(uint256(1)));
        pool.shield{value: 2 ether}(bytes32(uint256(1)));
    }

    function test_duplicate_output_is_noop() public {
        ShieldedPool.Spend memory s = _shieldA();
        pool.shield{value: _u(".transfer.out_value1")}(_s(".transfer.out_inner1"));
        require(pool.isLeaf(s.outCm1), "pre-seeded output leaf");
        uint32 before = pool.nextIndex();
        vm.prank(address(pool));
        pool.transfer(s);
        assertTrue(pool.nextIndex() == before + 1, "only the change note appended");
    }

    // ---- EIP-8272 publish through the proxy ----

    function test_publish_root_calls_native_predeploy() public {
        vm.expectCall(RECENT_ROOT_PREDEPLOY, abi.encodePacked(SALT, _s(".transfer.root")));
        pool.shield{value: _u(".shield_value")}(_s(".inner_a"));
    }

    // ---- differential vs ShieldedPool.sol: shield-sequence state parity ----

    /// The dispatcher's settlement is ShieldedPoolLogic, a variant of the
    /// ShieldedPool.sol spec. Drive both with the same shield sequence and
    /// assert identical tree state, so any layout/hash/root divergence fails.
    function testFuzz_shield_parity_vs_spec(bytes32 seed) public {
        ShieldedPool spec = new ShieldedPool(address(0x5EEDED), address(probe), verifier);
        for (uint256 i = 0; i < 12; i++) {
            bytes32 r = keccak256(abi.encode(seed, i));
            uint256 kind = uint256(r) % 4;
            bytes32 inner = bytes32(uint256(r) % P);
            uint256 value = (uint256(r) >> 16) % 4 ether + 1;
            if (kind == 3) value = 0; // ZeroValueShield on both
            (bool okP,) = address(pool).call{value: value}(abi.encodeWithSignature("shield(bytes32)", inner));
            (bool okS,) = address(spec).call{value: value}(abi.encodeWithSignature("shield(bytes32)", inner));
            assertTrue(okP == okS, "shield success diverged from spec");
            assertTrue(pool.currentRoot() == spec.currentRoot(), "root diverged from spec");
            assertTrue(pool.nextIndex() == spec.nextIndex(), "nextIndex diverged from spec");
        }
    }

    function assertTrue(bool c, string memory m) internal pure {
        require(c, m);
    }
}
