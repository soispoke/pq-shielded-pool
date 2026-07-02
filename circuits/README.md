# Spend circuit — reproduce the proving numbers

[`spend.py`](spend.py) is the leanVM zkDSL source for the spend circuit, with
its full soundness rationale in the docstring. Running `python3 spend.py`
checks it is byte-identical to the circuit embedded in
[`pool_circuits.patch`](pool_circuits.patch), which is what is actually proved
and verified.

The patch adds one test to `crates/lean_prover/src/test_zkvm.rs`:
`pool_spend_circuits` compiles the circuit at tree depths 20 and 32, builds a
real Poseidon Merkle authentication path, proves both a transfer and a withdraw,
asserts `verify_execution` passes, and asserts a tampered public claim is
rejected.

Upstream: `https://github.com/leanEthereum/leanVM.git`
Pinned commit: `12e61512416548e743040aab4daf83c58a5c5476`

```
git clone https://github.com/leanEthereum/leanVM.git
cd leanVM
git checkout 12e6151
git apply /path/to/this-repo/circuits/pool_circuits.patch
cargo build --release
cargo test --release -p lean_prover pool_spend_circuits -- --nocapture
```

Measured on an Apple M5 Max (WHIR rate 1/2):

| tree depth | operation | prove | proof | verify | tampered claim |
|---:|---|---:|---:|---:|---|
| 20 | transfer | 20.1 ms | 157.9 KiB | 18.0 ms | rejected |
| 20 | withdraw | 20.4 ms | 155.1 KiB | 16.1 ms | rejected |
| 32 | transfer | 23.1 ms | 154.5 KiB | 16.1 ms | rejected |
| 32 | withdraw | 27.9 ms | 155.0 KiB | 15.9 ms | rejected |

A spend proves in ~20-28 ms and verifies in ~16-18 ms regardless of tree depth
(the fixed VM overhead dominates at these sizes). At WHIR rate 1/4, the
fold-compatible regime for aggregation, the same circuit is smaller and faster
still (see the [recursive STARK mempool](https://github.com/soispoke/recursive-stark-mempool)
measurements), so these proofs drop straight into that aggregation pipeline.
