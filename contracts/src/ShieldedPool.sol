// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonBN254} from "./PoseidonBN254.sol";
import {Groth16Verifier} from "./Groth16Verifier.sol";
import {NonceManager} from "./NonceManager.sol";
import {RecentRoots} from "./RecentRoots.sol";

/// @title ShieldedPool — arbitrary-value join-split pool (BN254 / Groth16)
/// @notice An arbitrary-value join-split shielded pool on today's
///         cryptography, built to exercise two envelope features:
///
///         1. EIP-8250 MULTI-KEY nonces. A spend consumes TWO nullifiers as
///            one keyed-nonce set: `nonces.consumeFreshMany(sender, [nf1, nf2])`,
///            all at the shared nonce_seq = 0, atomically. A duplicate key in
///            the set is refused, which is also the same-note-twice defense:
///            spending one note through both circuit inputs yields nf1 == nf2
///            and the set consumption reverts. The VERIFY key-set binding
///            generalises to: consumed set == exactly {nf1, nf2}, no extras.
///
///         2. The TRUSTLESS-PAYMASTER fee binding. Every spend carries a
///            `fee` bound as a proof public signal; the contract pays it to
///            msg.sender from shielded value. On Sepolia msg.sender is the
///            pinned POOL_SENDER, so the pinned sender is reimbursed by the
///            notes it submits for: the fee story that the fixed-denomination
///            design foreclosed ("no value field, no fee skimming") closes
///            here. On a devnet the same binding funds an EIP-8141 paymaster
///            whose VERIFY frame checks it (see ../devnet/REVIEW.md).
///
///         Notes carry a 128-bit value: cm = Poseidon(TAG_LEAF, inner, value)
///         with inner = Poseidon2(owner_pk, rho). `shield` hashes msg.value
///         into the commitment ON-CHAIN, so a depositor cannot lie about a
///         deposit's value. The spend circuit proves conservation
///         (v_in1 + v_in2 = v_out1 + v_out2 + publicAmount + fee) over
///         range-checked values; a zero-value input is a dummy that skips the
///         membership check (it contributes nothing and its nullifier cannot
///         collide with a real note's). Outputs are always two commitments,
///         appended with the duplicate-no-op discipline.
///
///         Everything else is deliberately spare: pinned sender, RecentRoots
///         source binding, immutable, no owner, no admin.
contract ShieldedPool {
    uint32 public constant DEPTH = 20;
    bytes32 public constant SALT = bytes32(0); // the pool's root-source salt
    uint256 internal constant P = PoseidonBN254.P;
    uint256 internal constant MAX_VALUE = 1 << 128; // circuit range-check bound

    address public immutable POOL_SENDER;
    NonceManager public immutable nonces;
    RecentRoots public immutable roots;
    Groth16Verifier public immutable verifier;
    bytes32 public immutable sourceId; // EIP-8272 (address(this), SALT), fixed at deploy

    // filledSubtrees[l] = the latest completed left subtree at level l; slot
    // DEPTH is written (and read) only by the leaf that fills the tree.
    bytes32[DEPTH + 1] public filledSubtrees;
    uint32 public nextIndex;
    bytes32 public currentRoot;
    uint64 public lastRootSlot; // the slot currentRoot was published at (EIP-8272)
    mapping(bytes32 => bool) public isLeaf;

    event LeafAppended(bytes32 indexed cm, uint32 index, bytes32 newRoot, uint64 slot);
    event NoteSpent(bytes32 indexed nf);
    event Withdrawn(address indexed recipient, uint256 amount);
    event FeePaid(address indexed to, uint256 amount);

    error ZeroValueShield();
    error ValueTooLarge();
    error DuplicateCommitment();
    error NotCanonical();
    error TreeFull();
    error NotPoolSender();
    error ZeroNullifier();
    error RootNotRecentForPool();
    error ProofInvalid();
    error KeySetMismatch();
    error TransferShape();
    error WithdrawShape();
    error CtxDoesNotNameRecipient();
    error PayoutFailed();

    constructor(address poolSender, RecentRoots roots_, Groth16Verifier verifier_) {
        POOL_SENDER = poolSender;
        roots = roots_;
        verifier = verifier_;
        sourceId = roots_.sourceIdOf(address(this), SALT);
        nonces = new NonceManager(address(this));
        for (uint32 l = 0; l < DEPTH; l++) {
            filledSubtrees[l] = _zeros(l);
        }
        currentRoot = _zeros(DEPTH);
        _publishRoot();
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
        bytes32 root;
        uint64 slot; // the block the root was written in (EIP-8272 slot)
        bytes32 nf1;
        bytes32 nf2;
        bytes32 outCm1;
        bytes32 outCm2;
        uint256 publicAmount; // paid to the withdraw recipient (0 for transfer)
        uint256 fee;          // paid to msg.sender (the paymaster reimbursement)
        bytes32 ctx;
        uint256[2] pA; // the Groth16 proof, in snarkjs calldata form
        uint256[2][2] pB;
        uint256[2] pC;
    }

    /// Consume two notes, create two notes. Value stays shielded except the fee.
    function transfer(Spend calldata s) external {
        if (s.publicAmount != 0 || s.ctx != bytes32(0)) revert TransferShape();
        _spend(s);
        _settle(s);
    }

    /// Consume two notes, create two notes, and pay publicAmount to the
    /// recipient named by ctx (plus the fee to msg.sender).
    function withdraw(Spend calldata s, address payable recipient) external {
        if (s.publicAmount == 0 || s.ctx == bytes32(0)) revert WithdrawShape();
        if (s.ctx != ctxFor(recipient)) revert CtxDoesNotNameRecipient();
        _spend(s);
        _settle(s);
        emit Withdrawn(recipient, s.publicAmount);
        (bool ok,) = recipient.call{value: s.publicAmount}("");
        if (!ok) revert PayoutFailed();
    }

    /// Spend validity independent of who submits it: the non-zero nullifiers,
    /// the EIP-8272 recent-root binding, and the Groth16 proof over the eight
    /// public signals, bound directly in the circuit's order (outputs first,
    /// then public inputs). VIEW-only, so it is legal inside a VERIFY (static)
    /// frame: a paymaster staticcalls this to decide whether to APPROVE, and
    /// the protocol then consumes the nullifiers as keyed nonces at approval.
    /// It does not check the pinned sender (a VERIFY frame runs as ENTRY_POINT,
    /// not tx.sender), so that binding stays in the SENDER-frame path (_spend).
    /// Reverts on any failure. The canonicity and range guards duplicate the
    /// verifier's own field checks and the circuit's 128-bit range checks;
    /// they are kept for the named errors and as defense in depth.
    function verifySpend(Spend calldata s) public view {
        if (s.nf1 == bytes32(0) || s.nf2 == bytes32(0)) revert ZeroNullifier();
        if (!roots.check(sourceId, s.slot, s.root)) revert RootNotRecentForPool();
        _verifyProof(s);
    }

    /// verifySpend WITHOUT the recent-root check. Reads no storage (the
    /// verifier's key is in code, the field/range guards are on calldata), so a
    /// VERIFY-frame paymaster can STATICCALL it and still clear the ERC-7562
    /// observer's non-sender-SLOAD ban, which `roots.check` (a read of the
    /// RecentRoots contract) would trip. Approval is gated on the proof, which
    /// binds `root` as a public signal; root RECENCY is then enforced in the
    /// SENDER frame (verifySpend, via _spend). A stale or fabricated root
    /// therefore reverts in execution, consuming only the proven nullifiers,
    /// never a double-spend. See devnet/REVIEW.md.
    function verifyProofOnly(Spend calldata s) public view {
        if (s.nf1 == bytes32(0) || s.nf2 == bytes32(0)) revert ZeroNullifier();
        _verifyProof(s);
    }

    /// Shared: field canonicity, 128-bit value range, and the Groth16 proof
    /// over the eight public signals. No storage reads.
    function _verifyProof(Spend calldata s) internal view {
        if (uint256(s.root) >= P || uint256(s.nf1) >= P || uint256(s.nf2) >= P
            || uint256(s.outCm1) >= P || uint256(s.outCm2) >= P || uint256(s.ctx) >= P) {
            revert NotCanonical();
        }
        if (s.publicAmount >= MAX_VALUE || s.fee >= MAX_VALUE) revert ValueTooLarge();
        // Forward a fixed gas literal, not gas(): when verifyProofOnly runs in a
        // VERIFY frame the ERC-7562 observer bans the GAS opcode, and Solidity
        // would emit one for a default-gas external call. The EVM caps the
        // request at 63/64 of remaining gas. (Groth16Verifier's precompile
        // calls are patched to forward a fixed literal for the same reason.)
        if (!verifier.verifyProof{gas: 30000000}(s.pA, s.pB, s.pC,
            [uint256(s.nf1), uint256(s.nf2), uint256(s.outCm1), uint256(s.outCm2),
             uint256(s.root), s.publicAmount, s.fee, uint256(s.ctx)])) revert ProofInvalid();
    }

    /// The EIP-8250 spent-set binding as a pure check: the transaction's
    /// `nonce_keys` must be exactly the two proven nullifiers, distinct and
    /// sorted. Once the devnet exposes a `nonce_keys` TXPARAM selector, a
    /// VERIFY-frame paymaster reads the envelope's keys and calls this, so the
    /// consumed key set is proven equal to the nullifiers the proof commits to
    /// rather than trusted. (Today the pool enforces the same set from the
    /// SENDER frame via its own NonceManager; see _spend.)
    function checkKeySet(Spend calldata s, bytes32[] calldata nonceKeys) public pure {
        if (nonceKeys.length != 2 || s.nf1 == s.nf2) revert KeySetMismatch();
        bytes32 lo = s.nf1;
        bytes32 hi = s.nf2;
        if (uint256(lo) > uint256(hi)) (lo, hi) = (s.nf2, s.nf1);
        if (nonceKeys[0] != lo || nonceKeys[1] != hi) revert KeySetMismatch();
    }

    /// SENDER-frame binding checklist (see devnet/REVIEW.md). Today's shape
    /// verifies the proof here and consumes the nullifiers through the pool's
    /// own NonceManager. The faithful shape moves the proof check to a VERIFY
    /// frame (verifySpend) and the consumption to protocol keyed nonces bound
    /// by checkKeySet.
    function _spend(Spend calldata s) internal {
        // pinned sender: EIP-8250 key domains are per sender, so this pin is
        // what makes (POOL_SENDER, {nf}) a global spent set
        if (msg.sender != POOL_SENDER) revert NotPoolSender();
        verifySpend(s);
        // consume exactly {nf1, nf2} as ONE key set at nonce_seq 0 (atomic; a
        // duplicate key, the same note through both inputs, is refused here)
        bytes32[] memory keys = new bytes32[](2);
        keys[0] = s.nf1;
        keys[1] = s.nf2;
        nonces.consumeFreshMany(msg.sender, keys);
        emit NoteSpent(s.nf1);
        emit NoteSpent(s.nf2);
    }

    /// Post-consumption state changes shared by both operations: insert the
    /// two output notes (duplicate inserts are no-ops, never reverts),
    /// recompute and publish the new root once, then reimburse the submitter.
    /// Note the asymmetry: a failing fee/withdraw payout (PayoutFailed) or a
    /// full tree (TreeFull) reverts here, AFTER approval; harmless in this
    /// emulation (the whole tx reverts and nonces are restored), but under
    /// EIP-8250 approval-time consumption a post-approval revert would burn
    /// the nullifiers.
    function _settle(Spend calldata s) internal {
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
            emit FeePaid(msg.sender, s.fee);
            (bool ok,) = msg.sender.call{value: s.fee}("");
            if (!ok) revert PayoutFailed();
        }
    }

    // ---- encodings ----

    /// The withdraw context digest for a recipient: the address itself as one
    /// field element (a uint160 is always canonical). Must match the wallet.
    function ctxFor(address recipient) public pure returns (bytes32) {
        return bytes32(uint256(uint160(recipient)));
    }

    // ---- incremental Merkle tree ----

    function _hashPair(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return bytes32(PoseidonBN254.hash2(uint256(l), uint256(r)));
    }

    /// Write-only frontier insert (deposit-contract style): hash up while the
    /// index bit is 1, absorbing the filled left sibling, then record the
    /// completed subtree once at the first 0 bit. The root is recomputed
    /// separately (_computeRoot), so an operation inserting two leaves pays
    /// the 20-level path to the root once instead of twice, and every
    /// filledSubtrees write is one that a later hash actually reads.
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

    /// Root of an all-zero depth-l subtree. These depend only on DEPTH and
    /// the hash, so they live in code, not storage. Generated from
    /// reference/poseidon_bn254.py by zeros(l+1) = Poseidon2(zeros(l), zeros(l));
    /// zeros(DEPTH) is the empty tree's root, checked against the reference
    /// fixture in ../test/ShieldedPool.t.sol.
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

    /// Publish currentRoot to the EIP-8272 ring. Callers recompute and
    /// publish ONCE per operation after all inserts, so a spend's two leaves
    /// never materialise an intermediate root.
    function _publishRoot() internal {
        lastRootSlot = uint64(block.number);
        roots.write(SALT, currentRoot);
    }
}
