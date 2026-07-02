#!/usr/bin/env bash
# Standalone attester: verify a real leanVM proof off-chain, then sign
# (claim, proofHash) bound to a pool and chain. This is the trust shim standing
# in for the leanVM-verify precompile a real devnet supplies: the attester
# signs ONLY a proof it has verified, and anyone can re-run the same
# verify-spend on the posted proof to check the attester honest.
#
# Usage:  ATTESTER_PK=0x.. ./attest.sh <chainid> <pool> <publics_file> <proof_file>
# Prints: "<signature> <proofHash>"   (proofHash = sha256 of the proof file)
set -euo pipefail
cd "$(dirname "$0")"
CHAINID=$1; POOL=$2; PUBLICS=$3; PROOF=$4
DOMAIN=$(cast keccak "PQ_POOL_SPEND_ATTESTATION_V1")

# 1. verify the real STARK — the check the signature vouches for
../prover/target/release/verify-spend --proof "$PROOF" --publics "$PUBLICS" >/dev/null

# 2. bind the proof by its hash and the publics' claim, sign the raw digest
CLAIM=$(python3 -c "import json;print(json.load(open('$PUBLICS'))['claim_hex'])")
PROOFHASH=0x$(shasum -a 256 "$PROOF" | awk '{print $1}')
ENC=$(cast abi-encode "f(bytes32,uint256,address,bytes32,bytes32)" "$DOMAIN" "$CHAINID" "$POOL" "$CLAIM" "$PROOFHASH")
DIGEST=$(cast keccak "$ENC")
SIG=$(cast wallet sign --no-hash --private-key "$ATTESTER_PK" "$DIGEST")
echo "$SIG $PROOFHASH"
