// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title AttestedVerifier — the explicit trust shim for Sepolia
/// @notice No EVM path exists to verify a leanVM WHIR STARK (the devnet's
///         missing ingredient, see devnet/README.md). On Sepolia a designated
///         attester runs `verify-spend` off-chain and signs (claim, proofHash);
///         this contract only checks that signature. Anyone can re-verify a
///         posted proof against its claim with the published binary, so the
///         attester is a liveness shim for the demo, NOT a hidden oracle, and
///         this contract is exactly the trust boundary a real devnet deletes.
/// @dev    The signed digest binds the chain, the calling pool, the claim,
///         and the proof hash, so an attestation cannot be replayed across
///         chains, pool instances, or proofs.
contract AttestedVerifier {
    bytes32 public constant ATTESTATION_DOMAIN = keccak256("PQ_POOL_SPEND_ATTESTATION_V1");
    address public immutable attester;

    constructor(address attester_) {
        attester = attester_;
    }

    function attestationDigest(address pool, bytes32 claim, bytes32 proofHash)
        public
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(ATTESTATION_DOMAIN, block.chainid, pool, claim, proofHash));
    }

    /// Called by the pool; `msg.sender` is the pool being bound.
    function isAttested(bytes32 claim, bytes32 proofHash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        if (signature.length != 65) return false;
        bytes32 digest = attestationDigest(msg.sender, claim, proofHash);
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == attester;
    }
}
