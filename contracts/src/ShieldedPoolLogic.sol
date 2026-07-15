// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "./PoseidonBN254.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";

/// @title ShieldedPoolLogic — settlement implementation for the pool-as-sender
///         dispatcher (devnet/ShieldedPoolDispatcher.yul)
/// @notice The production-preferred split of the pool-as-sender design: the
///         frame-opcode shell that must be Yul is an immutable ~100-line
///         dispatcher deployed at the pool address; this Solidity contract
///         holds the settlement, tree, and claim logic and is reached only by
///         DELEGATECALL from that dispatcher. So `address(this)`, `msg.sender`,
///         `msg.value`, and storage are all the dispatcher's (the pool's) when
///         this code runs, and the fund-holding surface that needs a hand
///         audit shrinks to the dispatcher.
///
///         This is the same settlement semantics as ShieldedPool.sol (the
///         standalone reference), with exactly the deltas the split forces:
///
///         1. The pool IS its own sender. The pin is `msg.sender ==
///            address(this)` (a frame-2 SENDER self-call from the pool)
///            instead of a separate immutable POOL_SENDER. No poolSender
///            constructor argument.
///         2. `sourceId()` and `domain()` are computed at call time from
///            `address(this)` rather than baked as immutables. Immutables live
///            in the IMPLEMENTATION's code and would resolve to the logic
///            contract's own deploy address; under DELEGATECALL the pool needs
///            them derived from the dispatcher address, which only a runtime
///            computation gives. They read no storage, so verifyProofOnly
///            stays SLOAD-free for the VERIFY-frame paymaster.
///
///         The dispatcher's own constructor seeds the pool's currentRoot and
///         publishes the empty root; this contract's constructor does the same
///         in the logic's own (unused) storage so the logic stays self
///         consistent if ever called directly. Equivalence to ShieldedPool.sol
///         is enforced by contracts/test/DispatcherPool.t.sol (ported battery
///         plus a differential harness treating ShieldedPool.sol as the spec).
contract ShieldedPoolLogic {
    uint32 public constant DEPTH = 20;
    bytes32 public constant SALT = bytes32(0); // the pool's root-source salt
    uint256 internal constant P = PoseidonBN254.P;
    uint256 internal constant MAX_VALUE = 1 << 128; // circuit range-check bound
    uint256 internal constant VERIFIER_GAS_LIMIT = 500_000;
    bytes32 public constant DOMAIN_TAG = 0x40752e102d2a749c61d42a71e297edd3b493de639003b9480a700d589d98065b;
    // The EIP-8272 predeploy (0x…8272 on ethrex's Hegotá build). Empty code:
    // ethrex intercepts CALL-family invocations natively; on anvil/Forge a
    // call to it is a no-op success unless a test etches a recorder there.
    address public constant RECENT_ROOT_PREDEPLOY = address(0x8272);

    /// Stateless Yul envelope reader (devnet/EnvelopeProbe.yul): returns the
    /// eleven envelope words _spend binds. A separate contract because Solidity
    /// cannot emit the frame-tx opcodes (verbatim is Yul-object-only). Read
    /// from the implementation's code under DELEGATECALL, so it is the same
    /// fixed address regardless of the executing context.
    address public immutable probe;
    Groth16Verifier public immutable verifier;

    // Storage layout MUST match the Yul dispatcher's expectations and
    // ShieldedPool.sol: filledSubtrees 0..20, nextIndex 21, currentRoot 22,
    // isLeaf 23, withdrawalCredit 24, feeCredit 25. The dispatcher declares no
    // storage of its own; every slot here is a slot of the pool.
    bytes32[DEPTH + 1] public filledSubtrees;
    uint32 public nextIndex;
    bytes32 public currentRoot;
    mapping(bytes32 => bool) public isLeaf;
    mapping(address => uint256) public withdrawalCredit;
    mapping(address => uint256) public feeCredit;

    event LeafAppended(bytes32 indexed cm, uint32 index, bytes32 newRoot, uint64 slot);
    event NoteSpent(bytes32 indexed nf);
    event Withdrawn(address indexed recipient, uint256 amount);
    event FeePaid(address indexed to, uint256 amount);
    event WithdrawalCredited(address indexed recipient, uint256 amount);
    event FeeCredited(address indexed recipient, uint256 amount);

    error ZeroValueShield();
    error ValueTooLarge();
    error DuplicateCommitment();
    error NotCanonical();
    error TreeFull();
    error NotPoolSender();
    error ZeroNullifier();
    error NotFrameNative();
    error NotFaithfulShape();
    error RootNotBoundToReference();
    error ProofInvalid();
    error InvalidDomain();
    error KeySetMismatch();
    error TransferShape();
    error WithdrawShape();
    error CtxDoesNotNameRecipient();
    error PayoutFailed();
    error InvalidPayer();
    error NoCredit();
    error RootPublishFailed();
    error InvalidProbe();
    error InvalidVerifier();

    constructor(address probe_, Groth16Verifier verifier_) {
        if (probe_ == address(0) || probe_.code.length == 0) revert InvalidProbe();
        if (address(verifier_) == address(0) || address(verifier_).code.length == 0) revert InvalidVerifier();
        probe = probe_;
        verifier = verifier_;
        // Logic-standalone consistency only; the pool's initial state is set by
        // the dispatcher's constructor in the pool's storage.
        currentRoot = _zeros(DEPTH);
        _publishRoot();
    }

    // ---- identity (runtime, from address(this) so it is correct under
    // DELEGATECALL where address(this) is the dispatcher/pool) ----

    /// ethrex's native-write namespace: keccak256(pad32(this) || SALT). Same
    /// selector and value as ShieldedPool.sol's immutable getter, but computed
    /// from the executing address rather than the logic's deploy address.
    function sourceId() public view returns (bytes32) {
        return keccak256(abi.encode(address(this), SALT));
    }

    /// H(chain_id, sourceId) reduced into BN254 Fr.
    function domain() public view returns (bytes32) {
        return domainFor(block.chainid, sourceId());
    }

    // ---- operations ----

    /// Deposit any amount. The caller reveals only `inner` (hiding owner and
    /// rho); the contract hashes msg.value into the commitment itself, so the
    /// note's value is exactly what was deposited.
    function shield(bytes32 inner) external payable returns (uint32 index) {
        if (msg.value == 0) revert ZeroValueShield();
        if (msg.value >= MAX_VALUE) revert ValueTooLarge();
        if (uint256(inner) >= P) revert NotCanonical();
        bytes32 cm = bytes32(PoseidonBN254.hash3(2, uint256(inner), msg.value));
        // a duplicate commitment shares one nullifier, so the second deposit
        // would be permanently unspendable; reject it (wallets use a fresh rho)
        if (isLeaf[cm]) revert DuplicateCommitment();
        index = _insert(cm);
        currentRoot = _computeRoot();
        emit LeafAppended(cm, index, currentRoot, uint64(block.number));
        _publishRoot();
    }

    struct Spend {
        bytes32 root; // recency comes from the declared EIP-8272 reference
        bytes32 domain;
        bytes32 nf1;
        bytes32 nf2;
        bytes32 outCm1;
        bytes32 outCm2;
        uint256 publicAmount; // paid to the withdraw recipient (0 for transfer)
        uint256 fee; // credited to the authenticated transaction payer
        bytes32 ctx;
        uint256[2] pA; // the Groth16 proof, in snarkjs calldata form
        uint256[2][2] pB;
        uint256[2] pC;
    }

    /// Consume two notes and create two notes. Value stays shielded except the
    /// proof-bound fee, which is credited to the authenticated transaction
    /// payer returned by TXPARAM(0x11).
    function transfer(Spend calldata s) external {
        if (s.publicAmount != 0 || s.ctx != bytes32(0)) revert TransferShape();
        address payer = _spend(s);
        _settle(s, payer);
    }

    /// Consume two notes, create two notes, and pay publicAmount to the
    /// recipient named by ctx. The proof-bound fee is credited separately to
    /// the authenticated transaction payer.
    function withdraw(Spend calldata s, address recipient) external {
        if (s.publicAmount == 0 || s.ctx == bytes32(0)) revert WithdrawShape();
        if (s.ctx != ctxFor(recipient)) revert CtxDoesNotNameRecipient();
        address payer = _spend(s);
        _settle(s, payer);
        withdrawalCredit[recipient] += s.publicAmount;
        emit WithdrawalCredited(recipient, s.publicAmount);
    }

    /// Proof and canonicity, calldata-only. Reads no storage (the verifier's
    /// key is in code, the field/range guards are on calldata, domain() is
    /// computed from address/chainid), so a VERIFY-frame paymaster can
    /// STATICCALL it and clear the ERC-7562 observer's non-sender-SLOAD ban.
    /// Root recency is NOT checked here or anywhere in the pool: the declared
    /// EIP-8272 reference carries it, the protocol validates the reference at
    /// admission and block execution, and _spend requires the reference to
    /// equal (sourceId(), s.root).
    function verifyProofOnly(Spend calldata s) public view {
        if (s.nf1 == bytes32(0) || s.nf2 == bytes32(0)) revert ZeroNullifier();
        _verifyProof(s);
    }

    /// Shared: field canonicity, 128-bit value range, and the Groth16 proof
    /// over the nine public signals. No storage reads.
    function _verifyProof(Spend calldata s) internal view {
        if (s.domain != domain()) revert InvalidDomain();
        if (
            uint256(s.root) >= P || uint256(s.nf1) >= P || uint256(s.nf2) >= P || uint256(s.outCm1) >= P
                || uint256(s.outCm2) >= P || uint256(s.domain) >= P || uint256(s.ctx) >= P
        ) {
            revert NotCanonical();
        }
        if (s.publicAmount >= MAX_VALUE || s.fee >= MAX_VALUE) revert ValueTooLarge();
        // Forward a fixed gas literal, not gas(): when verifyProofOnly runs in a
        // VERIFY frame the ERC-7562 observer bans the GAS opcode, and Solidity
        // would emit one for a default-gas external call. The EVM caps the
        // request at 63/64 of remaining gas. (Groth16Verifier's precompile
        // calls are patched to forward a fixed literal for the same reason.)
        if (!verifier.verifyProof{gas: VERIFIER_GAS_LIMIT}(
                s.pA,
                s.pB,
                s.pC,
                [
                    uint256(s.nf1),
                    uint256(s.nf2),
                    uint256(s.outCm1),
                    uint256(s.outCm2),
                    uint256(s.root),
                    uint256(s.domain),
                    s.publicAmount,
                    s.fee,
                    uint256(s.ctx)
                ]
            )) {
            revert ProofInvalid();
        }
    }

    /// Settle-only SENDER-frame spend: the protocol consumed the keyed nonces
    /// at payment approval, so this only checks that THIS transaction is the
    /// one that consumed exactly the proven nullifiers, that the proven root
    /// rides as the transaction's protocol-validated recent-root reference,
    /// and that the authenticated values remain canonical; then it settles.
    /// The dispatcher already proved the byte-exact Spend in frame 0. The pool
    /// keeps no spent set and no root history.
    ///
    /// The proof re-verification that ShieldedPool.sol and the monolith keep
    /// here is REDUNDANT for the pool-as-sender dispatcher: execution approval
    /// with scope 0x2 can only come from a VERIFY frame targeting tx.sender,
    /// i.e. the dispatcher's own immutable frame-0 code, which already verified
    /// the proof over the byte-exact frame-2 Spend (see the single-verification
    /// analysis in devnet/REVIEW.md and its narrow dependence on the
    /// dispatcher-implementation binding being immutable). This implementation
    /// therefore calls _validateSpend (canonicity/range, no pairing) and leaves
    /// the full proof check to frame 0 and the paymaster carrier.
    function _spend(Spend calldata s) internal returns (address payer) {
        // pool-as-sender pin: the frame-2 SENDER frame runs with the pool as
        // caller (the pool is tx.sender), so under DELEGATECALL msg.sender is
        // the dispatcher == address(this). EIP-8250 key domains are per sender,
        // so this pin is what makes (pool, {nf}) a global spent set.
        if (msg.sender != address(this)) revert NotPoolSender();
        if (s.nf1 == bytes32(0) || s.nf2 == bytes32(0)) revert ZeroNullifier();
        // Envelope facts via the probe. Gas-capped: outside a frame
        // transaction the opcodes exceptional-halt and consume everything
        // forwarded, so cap the burn and turn it into a named revert. 100k
        // leaves generous headroom over the probe's fixed introspection
        // opcodes (attacker cannot inflate the count) against future
        // opcode repricing.
        (bool ok, bytes memory ret) = probe.staticcall{gas: 100_000}("");
        if (!ok || ret.length != 352) revert NotFrameNative();
        (
            uint256 frames,
            uint256 frameIndex,
            uint256 keyCount,
            uint256 nonceSeq,
            bytes32 k0,
            bytes32 k1,
            uint256 refCount,
            bytes32 refSource,
            bytes32 refRoot,
            address settleTarget,
            uint256 payerWord
        ) = abi.decode(
            ret, (uint256, uint256, uint256, uint256, bytes32, bytes32, uint256, bytes32, bytes32, address, uint256)
        );
        // Exactly-once per consumption. The faithful grammar has ONE settle
        // frame, index 2 of 3, and the protocol calls each frame's target
        // once. Requiring frame 2 to target THIS pool directly means the
        // single frame-2 call is the only entry: a settle frame pointing at
        // some intermediary has settleTarget != this and cannot double-credit
        // against one protocol nonce consumption.
        if (frames != 3 || frameIndex != 2 || settleTarget != address(this)) revert NotFaithfulShape();
        // the protocol's consumed key set == exactly the proven nullifiers
        // (strictly increasing at consensus, so matching {lo, hi} also
        // rejects nf1 == nf2)
        bytes32 lo = s.nf1;
        bytes32 hi = s.nf2;
        if (uint256(lo) > uint256(hi)) (lo, hi) = (s.nf2, s.nf1);
        if (keyCount != 2 || nonceSeq != 0 || k0 != lo || k1 != hi) revert KeySetMismatch();
        // the proven root == the declared, protocol-validated reference
        if (refCount != 1 || refSource != sourceId() || refRoot != s.root) revert RootNotBoundToReference();
        if (payerWord == 0 || payerWord > type(uint160).max) revert InvalidPayer();
        // Safe: the preceding bound proves that truncation cannot discard bits.
        // forge-lint: disable-next-line(unsafe-typecast)
        payer = address(uint160(payerWord));
        _validateSpend(s);
        emit NoteSpent(s.nf1);
        emit NoteSpent(s.nf2);
    }

    /// The cheap canonicity/range checks _verifyProof runs before the pairing
    /// call, kept in settlement so ABI/state behavior is unchanged, without a
    /// second pairing. These are exactly the checks that reject non-canonical
    /// nullifiers (nf + P) and over-range amounts independently of the proof.
    function _validateSpend(Spend calldata s) internal view {
        if (s.domain != domain()) revert InvalidDomain();
        if (
            uint256(s.root) >= P || uint256(s.nf1) >= P || uint256(s.nf2) >= P || uint256(s.outCm1) >= P
                || uint256(s.outCm2) >= P || uint256(s.domain) >= P || uint256(s.ctx) >= P
        ) {
            revert NotCanonical();
        }
        if (s.publicAmount >= MAX_VALUE || s.fee >= MAX_VALUE) revert ValueTooLarge();
    }

    /// Post-consumption state changes shared by both operations: insert the
    /// two output notes (duplicate inserts are no-ops, never reverts),
    /// recompute and publish the new root once, then record the fee as a
    /// pull credit (claimFee).
    function _settle(Spend calldata s, address payer) internal {
        uint32 i1;
        uint32 i2;
        bool new1 = !isLeaf[s.outCm1];
        if (new1) i1 = _insert(s.outCm1);
        bool new2 = !isLeaf[s.outCm2];
        if (new2) i2 = _insert(s.outCm2);
        if (new1 || new2) {
            currentRoot = _computeRoot();
            uint64 slot = uint64(block.number);
            if (new1) emit LeafAppended(s.outCm1, i1, currentRoot, slot);
            if (new2) emit LeafAppended(s.outCm2, i2, currentRoot, slot);
        }
        _publishRoot();
        if (s.fee != 0) {
            feeCredit[payer] += s.fee;
            emit FeeCredited(payer, s.fee);
        }
    }

    // ---- encodings ----

    /// The withdraw context digest for a recipient: the address itself as one
    /// field element (a uint160 is always canonical). Must match the wallet.
    function ctxFor(address recipient) public pure returns (bytes32) {
        return bytes32(uint256(uint160(recipient)));
    }

    /// keccak256(DOMAIN_TAG || uint256_be(chainId) || sourceId) reduced into Fr.
    function domainFor(uint256 chainId, bytes32 source) public pure returns (bytes32) {
        return bytes32(uint256(keccak256(abi.encodePacked(DOMAIN_TAG, chainId, source))) % P);
    }

    /// Pull-payment claims. ANYONE may push a party's recorded credit to that
    /// party: the amount is what settlement recorded for `who`, and it is sent
    /// to `who` itself (no redirect). This lets a passive contract recipient
    /// (the faithful-shape paymaster) collect its fee. The credit is zeroed
    /// before the send, so a `who` that reverts on receipt reverts only its own
    /// claim and keeps the credit for a later retry; a re-entrant claim sees a
    /// zero credit and reverts NoCredit.
    function claimWithdrawal(address payable who) external {
        uint256 amount = withdrawalCredit[who];
        if (amount == 0) revert NoCredit();
        withdrawalCredit[who] = 0;
        emit Withdrawn(who, amount);
        (bool ok,) = who.call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    function claimFee(address payable who) external {
        uint256 amount = feeCredit[who];
        if (amount == 0) revert NoCredit();
        feeCredit[who] = 0;
        emit FeePaid(who, amount);
        (bool ok,) = who.call{value: amount}("");
        if (!ok) revert PayoutFailed();
    }

    // ---- incremental Merkle tree ----

    function _hashPair(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return bytes32(PoseidonBN254.hash2(uint256(l), uint256(r)));
    }

    /// Write-only frontier insert (deposit-contract style): hash up while the
    /// index bit is 1, absorbing the filled left sibling, then record the
    /// completed subtree once at the first 0 bit. The root is recomputed
    /// separately (_computeRoot), so an operation inserting two leaves pays
    /// the 20-level path to the root once instead of twice.
    function _insert(bytes32 cm) internal returns (uint32 index) {
        index = nextIndex;
        if (index >= uint32(1) << DEPTH) revert TreeFull();
        nextIndex = index + 1;
        isLeaf[cm] = true;
        bytes32 node = cm;
        uint32 idx = index;
        uint32 l = 0;
        while (idx & 1 == 1) {
            node = _hashPair(filledSubtrees[l], node);
            idx >>= 1;
            l++;
        }
        filledSubtrees[l] = node; // l == DEPTH only for the leaf filling the tree
    }

    /// Root of the current tree: hash the next empty position (an all-zero
    /// subtree) up the frontier, pairing with the filled left sibling where
    /// the index bit is 1 and the all-zero right sibling where it is 0. A
    /// full tree has no empty position; its root is the completed level-DEPTH
    /// subtree recorded by the final _insert.
    function _computeRoot() internal view returns (bytes32 node) {
        uint32 idx = nextIndex;
        if (idx == uint32(1) << DEPTH) return filledSubtrees[DEPTH];
        for (uint32 l = 0; l < DEPTH; l++) {
            node = idx & 1 == 0 ? _hashPair(node, _zeros(l)) : _hashPair(filledSubtrees[l], node);
            idx >>= 1;
        }
    }

    /// Root of an all-zero depth-l subtree. Generated from
    /// reference/poseidon_bn254.py by zeros(l+1) = Poseidon2(zeros(l), zeros(l)).
    function _zeros(uint32 l) internal pure returns (bytes32) {
        if (l == 0) return bytes32(0);
        if (l == 1) return 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864;
        if (l == 2) return 0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1;
        if (l == 3) return 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238;
        if (l == 4) return 0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a;
        if (l == 5) return 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55;
        if (l == 6) return 0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78;
        if (l == 7) return 0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d;
        if (l == 8) return 0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61;
        if (l == 9) return 0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747;
        if (l == 10) return 0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2;
        if (l == 11) return 0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636;
        if (l == 12) return 0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a;
        if (l == 13) return 0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0;
        if (l == 14) return 0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c;
        if (l == 15) return 0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92;
        if (l == 16) return 0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323;
        if (l == 17) return 0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992;
        if (l == 18) return 0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f;
        if (l == 19) return 0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca;
        return 0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e; // l == DEPTH
    }

    /// Publish currentRoot to the EIP-8272 predeploy (the pool's ONLY root
    /// store): the 64-byte `SALT || root` native write, committed under
    /// keccak256(pad32(address(this)) || SALT) at the current consensus slot.
    function _publishRoot() internal {
        (bool ok,) = RECENT_ROOT_PREDEPLOY.call(abi.encodePacked(SALT, currentRoot));
        if (!ok) revert RootPublishFailed();
    }
}
