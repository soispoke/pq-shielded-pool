# Shared-sender adversarial suite vectors (Hegotá, 2026-07-12)

Raw inputs and recorded outputs for the live validation in REVIEW.md
"Production shared sender validated live (2026-07-12)". Archived so the run
can be audited from its exact inputs, and so future suites keep the habit.

## Deployment under test

`deploy_config.json` is the live configuration: pool
`0x7cFD0Ea4F7eB30aC04c389684a5025d5b32A55eE`, shared sender
`0x27cc5Cd97A65981d24d05e3fC2d03AEc69750BC1` (mutually bound by CREATE
precompute), paymaster A `0x66e5efe3…`, paymaster B `0xc72a24f2…`, and the
13-byte always-approve malicious payer `0x7395a10b…` (runtime
`3615600b5760015f5faa005b00`). `smoke_fixture.json` carries the
deployment-bound Groth16 proofs (chain 3151908, source id `0x8fbd9bed…`).
`bad_proof_fixture.json` is identical except the low bit of the transfer
proof's `pA[0]` is flipped. The outer signer for every spend was the
freshly generated, zero-balance key `0x05dD3932046b740Edff88e3B3dEAA2ad1a0BD79D`.

## Commands and recorded results

All commands run from `devnet/` with this directory's files in place of the
live config and fixture paths. `SENDER=0x27cc5cd97a65981d24d05e3fc2d03aec69750bc1`,
`MAL=0x7395a10b1168f3a70a560a4ea56b9168a4d56186`.

Honest transfer (mined `0x0af5a301…`, block 142399, 1,744,804 gas; frame gas
f0=250,824 f1=42,355 f2=1,408,046; payer resolved to paymaster A):

    pool_frametx.py <rpc> deploy_config.json smoke_fixture.json transfer \
        <signer_priv> --sender $SENDER --save-raw transfer_raw.hex

Honest withdraw (mined `0xad0e83de…`, block 142406, 1,884,797 gas; payer
resolved to paymaster B):

    pool_frametx.py <rpc> deploy_config.json smoke_fixture.json withdraw \
        <signer_priv> --sender $SENDER --paymaster 0xc72a24f26fac608fa6c196689085a3656dc7b73e

Bad proof through the malicious payer (recorded: `valid=False payer=None
violation=validation prefix frame reverted`):

    pool_frametx.py <rpc> deploy_config.json bad_proof_fixture.json transfer \
        <signer_priv> --sender $SENDER --paymaster $MAL --dry-run

Wrong nonce keys through the malicious payer (same recorded rejection):

    pool_frametx.py <rpc> deploy_config.json smoke_fixture.json transfer \
        <signer_priv> --sender $SENDER --paymaster $MAL --dry-run \
        --nonce-keys 0x0abc123456789def0abc123456789def0abc123456789def0abc123456789de,0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde

Down-gassed settlement through the malicious payer (same recorded rejection):

    pool_frametx.py <rpc> deploy_config.json smoke_fixture.json transfer \
        <signer_priv> --sender $SENDER --paymaster $MAL --dry-run \
        --settle-gas 5000000

Fee boundary against honest paymaster A (fee fixed at 0.05 ETH by the proof;
recorded: max_cost=50,000,000,000,721,585 at max-fee 4,787,636,255 rejected
with payer=None; max_cost=49,999,999,991,784,987 at max-fee 4,787,630,753
simulated valid with payer=A; accept/reject tracked fee >= TXPARAM(0x06)
exactly through the RLP-length-induced total-gas wobble, 10,443,555 to
10,443,579 gas):

    pool_frametx.py <rpc> deploy_config.json smoke_fixture.json transfer \
        <signer_priv> --sender $SENDER --dry-run --max-fee-per-gas <P>

Replay (recorded RPC error: `Nonce mismatch: expected 1, got 0`, rejected at
admission, not mined-and-reverted):

    eth_sendRawTransaction with the contents of transfer_raw.hex

## Replayability

The keyed nonces of both honest spends are consumed on Hegotá, which is the
point of the design, so the vectors split into three classes. The
`transfer_raw.hex` replay is permanently rejected at admission (nonce mismatch
now; reference recency once the declared root ages past the 8192-slot window).
The wrong-key simulation replays with its original frame-0 rejection until
that same window closes, since its override keys stay unconsumed. The
bad-proof, down-gas, and fee-boundary simulations are frozen history: they
embed the consumed transfer nullifiers as nonce keys, so re-running them now
fails at keyed-nonce validation before reaching the frame that originally
rejected. Their inputs are archived here byte-exact, their outputs were
recorded above at run time, and reproducing the frame-level rejection needs a
fresh deployment and fixture, for which the commands are the specification.
