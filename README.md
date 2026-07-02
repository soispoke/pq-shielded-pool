# PQ shielded pool

A minimal, post-quantum, Tornado-style privacy pool for Ethereum. Fixed
denomination, no token, no governance, no admin key, no compliance hooks: an
immutable contract with exactly three operations (shield, transfer, withdraw)
and a leanVM STARK that proves ownership without revealing it.

Built to run in an EIP-8141 / EIP-8250 / EIP-8272 devnet, so a user's private
transaction is an ordinary frame transaction: the base protocol supplies the
spent-once keys and recent-roots ring, and the pool's own `VERIFY` logic binds
them to each proof. See [devnet/](devnet/README.md).

**New here? Start with [EXPLAINER.md](EXPLAINER.md).**

## What it is

- **Post-quantum**: the only cryptography is hashing (Poseidon2 over KoalaBear,
  via leanVM). No elliptic curves anywhere. Ownership is knowledge of a hash
  preimage, membership is a Merkle proof, and the whole spend is one leanVM
  STARK, all quantum-resistant. (Honest caveat: leanVM's hash security is
  ~124-bit classical / ~62-bit quantum today, so "PQ" is directional, not yet
  128-bit; and the circuit is unaudited.)
- **Minimal**: fixed-denomination notes mean there is no value field, hence no
  in-circuit balance arithmetic and no range checks, the largest soundness
  footgun in a 31-bit field, deleted by design. The contract is a Merkle tree,
  a recent-roots ring, and a nullifier set. Nothing else.
- **Immutable and permissionless**: no owner, no upgrade path, no allowlist, no
  freezing, no viewing keys, no compliance backdoor.

## What a spend proves

Hiding the spend key, the note secret, and the Merkle path, the circuit proves:

> I own a note committed in the pool's tree at an anchored root, and I expose
> exactly one nullifier for it, one optional output note, and one context, all
> bound into a single public claim.

The five properties that make this a secure spend rather than a cost
demonstration are each enforced in-circuit, not assumed:

1. **Boolean path bits** so the Merkle path is well-formed.
2. **Root anchoring**: the computed root is folded into the public claim and
   the contract checks it against its recent-roots ring, so the prover cannot
   invent a tree.
3. **Domain separation**: owner key, leaf, nullifier, and claim each hash under
   a distinct tag, so no digest is reusable across roles.
4. **Key- and note-bound nullifier**: `nf = H(TAG_NULL, spend_key, cm)`,
   deterministic per note, computable only by the owner.
5. **Double-spend prevention**: the nullifier is published and the contract
   consumes it exactly once.

These are precisely the five caveats the [recursive STARK mempool](https://github.com/soispoke/recursive-stark-mempool)'s
cost-only spend circuit left open; this repo closes all five in a real circuit.

## Layout

```
circuits/
  spend.py             the leanVM zkDSL spend circuit (transfer + withdraw), with
                       its full soundness rationale and a drift guard
  pool_circuits.patch  the leanVM harness (proves + verifies both ops), vs commit 12e6151
  README.md            reproduce the proving numbers
pool/
  note.py              note, commitment, nullifier, and the spend relation (matches
                       the circuit; SHA-256 stands in for Poseidon2 so it runs in Python)
  pool.py              the immutable contract: Merkle tree + recent-roots ring + nullifier set
  demo.py              end-to-end: shield -> transfer -> withdraw, with double-spend
                       and forged-root both refused
devnet/
  README.md            how the pool maps onto EIP-8141 / 8250 / 8272, and the test plan
  flow.md              one private transfer traced field-by-field through the stack
docs/                  figures used by the explainer
```

## Run

```
# the whole protocol, in plain Python (self-checking):
python3 pool/demo.py

# check the circuit source matches the harness:
python3 circuits/spend.py

# prove and verify real spends on your machine (see circuits/README.md):
#   clone leanVM @ 12e6151, git apply circuits/pool_circuits.patch,
#   cargo test --release -p lean_prover pool_spend_circuits -- --nocapture
```

## Measured (Apple M5 Max, WHIR rate 1/2)

A spend (transfer or withdraw) proves in **~20-28 ms**, produces a
**~155-158 KiB** proof, and verifies in **~16-18 ms**, independent of tree
depth. Tampered claims are rejected. At WHIR rate 1/4 the same circuit is
smaller (the [recursive STARK mempool](https://github.com/soispoke/recursive-stark-mempool)
measured a comparable spend at ~108 KiB / ~17 ms prove), so these proofs feed
directly into that aggregation pipeline.

## Security posture

The five spend-circuit properties above are enforced in-circuit, and fixed
denomination removes value arithmetic. End-to-end devnet soundness additionally
requires the pool's on-chain `VERIFY` logic to (1) authenticate
`(sender, nonce_keys_hash, nonce_seq == 0)` and bind the consumed nonce key to
`nf` while rejecting extra keys (EIP-8250), and (2) bind the referenced
`(source_id, slot)` to the pool's own root source (EIP-8272); without these a
valid proof could be lifted into a different frame. See [devnet/](devnet/README.md).

Stated residual trust surface: leanVM's current ~124-bit classical / ~62-bit
quantum hash security (so "PQ" is directional, not yet 128-bit); the circuit and
contract are unaudited; the two contract-side bindings above are trusted, not
proven in-circuit; and this is a research prototype, not production software.

Privacy limits: anonymity equals the number of indistinguishable unspent notes
at spend time, a dynamic set that can be as small as 1 (a spend into a tiny pool
is linkable), so wallets should wait for a sufficient set and avoid
spend-soon-after-deposit timing. The circuit cannot hide the transaction sender
or the deposit's funding address; both are on-chain and must be decorrelated by
a shared/relayer sender. By design there is no compliance or viewing-key
mechanism.

## License

Apache-2.0 (see `LICENSE`). The Python model and circuit are original work;
`circuits/pool_circuits.patch` modifies `leanEthereum/leanVM` (Apache-2.0) at
commit `12e6151`; see `NOTICE`.
