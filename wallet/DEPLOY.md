# Deploying the pool and running the live flow — Sepolia milestone 5

`deploy_flow.sh` deploys the four contracts and runs the whole protocol
(`shield -> transfer -> withdraw`) against a live JSON-RPC node with real
leanVM proofs, signing each spend with a standalone attester that verifies the
proof off-chain first. It works against any node; with no arguments it spins up
a local anvil, which is a faithful dress rehearsal for Sepolia (same EVM, same
RPC, same signing path).

## Local (anvil) — proven

```
./smoke.sh          # once, to build the prover and generate real proofs
./deploy_flow.sh    # launches anvil, deploys, runs the flow, writes deploy_config.json
```

This deploys `RecentRoots`, `AttestedVerifier`, and `ShieldedPool` (which
creates its own `NonceManager`), shields Alice's note, runs her real-proof
transfer to Bob, and Bob's real-proof withdraw, asserting the payout. The
attester (`attest.sh`) runs `verify-spend` on each real proof before signing,
so the on-chain acceptance is downstream of an actual STARK verification.

## Sepolia

The only differences are credentials and that the broadcast is real and
irreversible, so it is never done implicitly. Provide:

```
export RPC_URL=https://sepolia.infura.io/v3/<key>     # or any Sepolia endpoint
export DEPLOYER_PK=0x...        # a funded Sepolia key (deploys + shields)
export POOL_SENDER_PK=0x...     # the pinned sender that submits spends (fund it)
export ATTESTER_PK=0x...        # the attester that verifies + signs
./deploy_flow.sh
```

`deploy_flow.sh` writes `deploy_config.json` with the deployed addresses, the
chain id, and the deployment block. Commit that file for a Sepolia deployment
(the anvil one is gitignored) so wallets and reviewers can pin the addresses
and scan from the deployment block, the way
[EIP-8182's demo](https://github.com/0xFacet/eip-8182-reference-implementation)
pins its Sepolia addresses.

Notes for a real deployment:

- Fund `POOL_SENDER`: it pays gas for every spend. This is exactly the open fee
  problem from `devnet/README.md`; on Sepolia the operator simply funds it.
- The attester is the trust shim. It signs only proofs it verified, and it
  posts the proof so anyone can re-run `verify-spend`. On a real devnet a
  leanVM-verify precompile replaces it; on Sepolia it is a labeled, honest
  stand-in, not a hidden oracle.
- Blocks: a root written in slot S is referenceable from S+1. Sepolia's ~12s
  blocks satisfy this naturally; the script reads `lastRootSlot()` after each
  publish and references it from the next transaction.
- `POOL_SENDER` is the only sender that can spend (EIP-8250 key domains are per
  sender), so keep its key with the relayer/attester process.

## What this does and does not prove

Proven end to end: the wallet reconstructs the tree, builds real witnesses,
proves them, the attester verifies and signs, and the pool accepts them live
for the full lifecycle. Still shimmed: on-chain proof verification (the
attester stands in for it, as designed). That boundary is the one a
patched-client devnet removes; see `../research`-linked notes.
