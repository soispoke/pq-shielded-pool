# wallet — Sepolia milestone 4: the wallet, indexer, and end-to-end smoke

The piece that ties the stack together. `wallet.py` reconstructs the note tree
from the pool's `LeafAppended` events (here: an ordered leaf list), computes
real Merkle authentication paths that match `ShieldedPool._append`, and builds
the spend witnesses the prover consumes. `gen_smoke.py` plays the whole
protocol with real leanVM proofs, and `smoke.sh` runs it end to end and then
on-chain.

## What the smoke proves

`shield -> transfer -> withdraw`, with a real STARK at each spend:

1. Alice shields note A. Her wallet rebuilds the tree (`[cm_A]`), computes the
   real auth path for leaf 0, and `prove-spend` proves the transfer to Bob.
2. `verify-spend` verifies that proof off-chain (the real STARK check).
3. The crux: the root the wallet computed for `[cm_A]` equals the root the
   prover put in the claim, which equals the root the pool republishes on
   `shield` (asserted on all three sides). Same for `[cm_A, cm_B]` and Bob's
   withdraw.
4. On-chain, the pool accepts each real claim through the attester shim and
   runs the transfer and withdraw; a replay of the withdraw is refused.

The attester signature stands in for the leanVM-verify precompile a real devnet
supplies (see `devnet/README.md`); the real proof is what `verify-spend`
checks in step 2, and its hash is bound in the attestation.

## Run

```
./smoke.sh              # build prover, prove (deterministic notes), verify, run on-chain
./smoke.sh --random     # fresh secrets each run
python3 wallet.py       # wallet self-check: tree matches the pool fixture, paths verify
```

`smoke.sh` writes `smoke_fixture.json` (committed, deterministic) and the real
proof files under `artifacts/` (gitignored, regenerable). The committed fixture
lets `contracts/`'s `forge test` run the on-chain half (`SmokeE2ETest`) without
regenerating proofs.

## Files

```
wallet.py         tree/indexer + note crypto + witness builder (Poseidon16)
gen_smoke.py      generate real proofs for Alice's transfer and Bob's withdraw,
                  verify them off-chain, assert wallet roots == prover roots,
                  write smoke_fixture.json
smoke.sh          the full end-to-end runner (in-process EVM)
deploy_flow.sh    deploy + run the flow against a live node (anvil or Sepolia)
attest.sh         standalone attester: verify-spend then sign (the trust shim)
DEPLOY.md         Sepolia deployment steps
smoke_fixture.json  committed, deterministic; drives contracts/test/SmokeE2E.t.sol
```

## Live deployment (milestone 5)

`deploy_flow.sh` deploys the four contracts and runs the whole flow against a
live JSON-RPC node (default: a local anvil it launches) with the real proofs,
signing each spend with a standalone attester (`attest.sh`) that verifies the
proof off-chain before signing:

```
./deploy_flow.sh              # anvil dress rehearsal, writes deploy_config.json
```

For Sepolia, set `RPC_URL`, `DEPLOYER_PK`, `POOL_SENDER_PK`, `ATTESTER_PK` and
run the same script. See [DEPLOY.md](DEPLOY.md). `attest.sh` is the standalone
attester: `verify-spend` then `cast wallet sign`, replacing the in-test signer.
