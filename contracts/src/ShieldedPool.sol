// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Poseidon16} from "./Poseidon16.sol";
import {NonceManager} from "./NonceManager.sol";
import {RecentRoots} from "./RecentRoots.sol";
import {AttestedVerifier} from "./AttestedVerifier.sol";

/// @title ShieldedPool — the immutable PQ shielded pool (Sepolia emulation)
/// @notice One-for-one with pool/pool.py and the devnet/README.md binding
///         checklist. State: an incremental Merkle tree of note commitments
///         (filled-subtree caching, Tornado-style) hashed with leanVM's
///         Poseidon16, plus a leaf set for duplicate handling. The spent set
///         lives in NonceManager (per-sender key domains, hence the pinned
///         POOL_SENDER), root freshness in RecentRoots, proof verification
///         behind AttestedVerifier. No owner, no upgrade path, no allowlist.
///
///         The four VERIFY bindings, each enforced in `_spend`:
///           1. pinned sender: msg.sender == POOL_SENDER;
///           2. key set: consume exactly (POOL_SENDER, nf), nf != 0;
///           3. root reference: (sourceId(), slot, root) valid in RecentRoots;
///           4. operation shape: transfer has ctx == 0 and outCm != 0,
///              withdraw has outCm == 0 and ctx naming the recipient.
///         Plus: a duplicate outCm append is a no-op success, never a revert
///         (on the devnet the nullifier is consumed at payment approval and
///         survives later-frame reverts, so a revert here would burn the note;
///         Sepolia reverts atomically, but the code keeps devnet discipline).
contract ShieldedPool {
    uint32 public constant DEPTH = 20;
    bytes32 public constant SALT = bytes32(0); // the pool's root-source salt

    uint256 public immutable DENOMINATION;
    address public immutable POOL_SENDER;
    NonceManager public immutable nonces;
    RecentRoots public immutable roots;
    AttestedVerifier public immutable verifier;

    bytes32[DEPTH] public zeros; // zeros[l] = root of an all-zero depth-l subtree
    bytes32[DEPTH] public filledSubtrees;
    uint32 public nextIndex;
    bytes32 public currentRoot;
    mapping(bytes32 => bool) public isLeaf;

    event LeafAppended(bytes32 indexed cm, uint32 index, bytes32 newRoot, uint64 slot);
    event NoteSpent(bytes32 indexed nf);
    event Withdrawn(address indexed recipient);

    error WrongDenomination();
    error DuplicateCommitment();
    error TreeFull();
    error NotPoolSender();
    error ZeroNullifier();
    error RootNotRecentForPool();
    error ProofNotAttested();
    error TransferShape();
    error WithdrawShape();
    error CtxDoesNotNameRecipient();
    error PayoutFailed();

    constructor(uint256 denomination, address poolSender, RecentRoots roots_, AttestedVerifier verifier_) {
        DENOMINATION = denomination;
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

    /// Deposit one denomination and append its note commitment. No proof.
    function shield(bytes32 cm) external payable returns (uint32 index) {
        if (msg.value != DENOMINATION) revert WrongDenomination();
        // a duplicate commitment shares one nullifier, so the second deposit
        // would be permanently unspendable; reject it (wallets use a fresh rho)
        if (isLeaf[cm]) revert DuplicateCommitment();
        return _append(cm);
    }

    struct Spend {
        bytes32 root;
        uint64 slot; // the block the root was written in (EIP-8272 slot)
        bytes32 nf;
        bytes32 outCm;
        bytes32 ctx;
        bytes32 proofHash;
        bytes attestation;
    }

    /// Consume a note, create the recipient's new note. Value stays shielded.
    function transfer(Spend calldata s) external {
        if (s.outCm == bytes32(0) || s.ctx != bytes32(0)) revert TransferShape();
        _spend(s);
        if (!isLeaf[s.outCm]) {
            _append(s.outCm);
        }
        // duplicate append: no-op success, see the contract-level notice above
    }

    /// Consume a note, pay one denomination to the recipient named by ctx.
    function withdraw(Spend calldata s, address payable recipient) external {
        if (s.outCm != bytes32(0) || s.ctx == bytes32(0)) revert WithdrawShape();
        if (s.ctx != ctxFor(recipient)) revert CtxDoesNotNameRecipient();
        _spend(s);
        emit Withdrawn(recipient);
        (bool ok,) = recipient.call{value: DENOMINATION}("");
        if (!ok) revert PayoutFailed();
    }

    /// The binding checklist from devnet/README.md, in order.
    function _spend(Spend calldata s) internal {
        // 1. pinned sender: EIP-8250 key domains are per sender, so this pin
        //    is what makes (POOL_SENDER, nf) a global spent set
        if (msg.sender != POOL_SENDER) revert NotPoolSender();
        if (s.nf == bytes32(0)) revert ZeroNullifier();
        // 3. the referenced root is this pool's own recent root
        if (!roots.check(sourceId(), s.slot, s.root)) revert RootNotRecentForPool();
        // recompute the claim from the publics and check the proof against it
        bytes32 claim = computeClaim(s.root, s.nf, s.outCm, s.ctx);
        if (!verifier.isAttested(claim, s.proofHash, s.attestation)) revert ProofNotAttested();
        // 2. consume exactly (POOL_SENDER, nf); reverts on double-spend
        nonces.consumeFresh(msg.sender, s.nf);
        emit NoteSpent(s.nf);
    }

    // ---- claim and encodings ----

    /// claim = H(TAG_CLAIM, H(root || nf), H(outCm || ctx)), over unpacked
    /// digests; rejects non-canonical encodings (unpackDigest reverts).
    function computeClaim(bytes32 root, bytes32 nf, bytes32 outCm, bytes32 ctx)
        public
        pure
        returns (bytes32)
    {
        uint256[8] memory c1 =
            Poseidon16.compressPair(Poseidon16.unpackDigest(root), Poseidon16.unpackDigest(nf));
        uint256[8] memory c2 =
            Poseidon16.compressPair(Poseidon16.unpackDigest(outCm), Poseidon16.unpackDigest(ctx));
        return Poseidon16.packDigest(Poseidon16.tagged(4, c1, c2));
    }

    /// The withdraw context digest for a recipient: the 160-bit address split
    /// into 8 big-endian 20-bit chunks, one per field element. Must match
    /// ctx_for_recipient in prover/src/lib.rs.
    function ctxFor(address recipient) public pure returns (bytes32) {
        uint256 a = uint256(uint160(recipient));
        uint256 acc;
        for (uint256 i = 0; i < 8; i++) {
            acc = (acc << 32) | ((a >> (140 - 20 * i)) & 0xfffff);
        }
        return bytes32(acc);
    }

    // ---- incremental Merkle tree ----

    function _hashPair(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        return Poseidon16.packDigest(
            Poseidon16.compressPair(Poseidon16.unpackDigest(l), Poseidon16.unpackDigest(r))
        );
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
        roots.write(SALT, currentRoot);
    }
}
