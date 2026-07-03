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
///            `fee` bound inside the claim; the contract pays it to
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

    bytes32[DEPTH] public zeros; // zeros[l] = root of an all-zero depth-l subtree
    bytes32[DEPTH] public filledSubtrees;
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
    error TransferShape();
    error WithdrawShape();
    error CtxDoesNotNameRecipient();
    error PayoutFailed();

    constructor(address poolSender, RecentRoots roots_, Groth16Verifier verifier_) {
        POOL_SENDER = poolSender;
        roots = roots_;
        verifier = verifier_;
        nonces = new NonceManager(address(this));
        bytes32 z = bytes32(0);
        for (uint32 l = 0; l < DEPTH; l++) {
            zeros[l] = z;
            filledSubtrees[l] = z;
            z = _hashPair(z, z);
        }
        currentRoot = z;
        _publishRoot();
    }

    function sourceId() public view returns (bytes32) {
        return roots.sourceIdOf(address(this), SALT);
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
        return _append(cm);
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

    /// The binding checklist from devnet/REVIEW.md, key set generalised.
    function _spend(Spend calldata s) internal {
        // 1. pinned sender: EIP-8250 key domains are per sender, so this pin
        //    is what makes (POOL_SENDER, {nf}) a global spent set
        if (msg.sender != POOL_SENDER) revert NotPoolSender();
        if (s.nf1 == bytes32(0) || s.nf2 == bytes32(0)) revert ZeroNullifier();
        // 3. the referenced root is this pool's own recent root
        if (!roots.check(sourceId(), s.slot, s.root)) revert RootNotRecentForPool();
        // recompute the claim from the publics; the proof is valid only for
        // exactly this claim (the single public signal)
        bytes32 claim = computeClaim(s);
        if (!verifier.verifyProof(s.pA, s.pB, s.pC, [uint256(claim)])) revert ProofInvalid();
        // 2. consume exactly {nf1, nf2} as ONE key set at nonce_seq 0
        //    (atomic; a duplicate key — the same note spent through both
        //    inputs — is refused here)
        bytes32[] memory keys = new bytes32[](2);
        keys[0] = s.nf1;
        keys[1] = s.nf2;
        nonces.consumeFreshMany(msg.sender, keys);
        emit NoteSpent(s.nf1);
        emit NoteSpent(s.nf2);
    }

    /// Post-consumption state changes shared by both operations: append the
    /// two output notes (duplicate appends are no-ops, never reverts), then
    /// reimburse the submitter.
    function _settle(Spend calldata s) internal {
        if (!isLeaf[s.outCm1]) _append(s.outCm1);
        if (!isLeaf[s.outCm2]) _append(s.outCm2);
        if (s.fee != 0) {
            emit FeePaid(msg.sender, s.fee);
            (bool ok,) = msg.sender.call{value: s.fee}("");
            if (!ok) revert PayoutFailed();
        }
    }

    // ---- claim and encodings ----

    /// claim = Poseidon(TAG_CLAIM, P3(root, nf1, nf2),
    ///                  P3(outCm1, outCm2, P3(publicAmount, fee, ctx)));
    /// rejects non-canonical digests and out-of-range amounts (the circuit
    /// range-checks 128 bits, so larger values could never have a proof).
    function computeClaim(Spend calldata s) public pure returns (bytes32) {
        if (uint256(s.root) >= P || uint256(s.nf1) >= P || uint256(s.nf2) >= P
            || uint256(s.outCm1) >= P || uint256(s.outCm2) >= P || uint256(s.ctx) >= P) {
            revert NotCanonical();
        }
        if (s.publicAmount >= MAX_VALUE || s.fee >= MAX_VALUE) revert ValueTooLarge();
        uint256 c1 = PoseidonBN254.hash3(uint256(s.root), uint256(s.nf1), uint256(s.nf2));
        uint256 c3 = PoseidonBN254.hash3(s.publicAmount, s.fee, uint256(s.ctx));
        uint256 c2 = PoseidonBN254.hash3(uint256(s.outCm1), uint256(s.outCm2), c3);
        return bytes32(PoseidonBN254.hash3(4, c1, c2));
    }

    /// The withdraw context digest for a recipient: the address itself as one
    /// field element (a uint160 is always canonical). Must match the wallet.
    function ctxFor(address recipient) public pure returns (bytes32) {
        return bytes32(uint256(uint160(recipient)));
    }

    // ---- incremental Merkle tree ----

    function _hashPair(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return bytes32(PoseidonBN254.hash2(uint256(l), uint256(r)));
    }

    function _append(bytes32 cm) internal returns (uint32 index) {
        index = nextIndex;
        if (index >= uint32(1) << DEPTH) revert TreeFull();
        nextIndex = index + 1;
        isLeaf[cm] = true;
        bytes32 node = cm;
        uint32 idx = index;
        for (uint32 l = 0; l < DEPTH; l++) {
            if (idx & 1 == 0) {
                filledSubtrees[l] = node;
                node = _hashPair(node, zeros[l]);
            } else {
                node = _hashPair(filledSubtrees[l], node);
            }
            idx >>= 1;
        }
        currentRoot = node;
        _publishRoot();
        emit LeafAppended(cm, index, node, uint64(block.number));
    }

    function _publishRoot() internal {
        lastRootSlot = uint64(block.number);
        roots.write(SALT, currentRoot);
    }
}
