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

- **Post-quantum**: the only cryptography is hashing (leanVM's Poseidon16,
  classic Poseidon over KoalaBear). No elliptic curves anywhere. Ownership is
  knowledge of a hash preimage, membership is a Merkle proof, and the whole
  spend is one leanVM STARK, all quantum-resistant. (Honest caveat: leanVM's hash security is
  ~124-bit classical / ~62-bit quantum today, so "PQ" is directional, not yet
  128-bit; and the circuit is unaudited.)
- **Minimal**: fixed-denomination notes mean there is no value field, hence no
  in-circuit balance arithmetic and no range checks, the largest soundness
  footgun in a 31-bit field, deleted by design. The contract is a Merkle tree
  plus a handful of envelope binding checks; the spent set and the recent-roots
  window live in the protocol (EIP-8250 / EIP-8272).
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
                       the circuit; SHA-256 stands in for Poseidon so it runs in Python)
  pool.py              the immutable contract: Merkle tree + recent-roots ring + nullifier set
  demo.py              end-to-end: shield -> transfer -> withdraw, with double-spend,
                       forged-root, and duplicate-output front-run all handled
  envelope.py          the devnet envelope: per-sender EIP-8250 keyed nonces, EIP-8272
                       windowed roots, and the pool's pinned-sender VERIFY checklist,
                       with the envelope-level attacks refused
devnet/
  README.md            how the pool maps onto EIP-8141 / 8250 / 8272, and the test plan
  flow.md              one private transfer traced field-by-field through the stack
prover/
  src/                 pool-prover: prove-spend / verify-spend / export-vectors
                       binaries against leanVM pinned as a git dependency; the
                       circuit is extracted from circuits/spend.py, never
                       duplicated (Sepolia milestone 2; see prover/README.md)
contracts/
  src/Poseidon16.sol   leanVM's hash (classic Poseidon over KoalaBear) in Solidity,
                       differentially tested against vectors exported from leanVM
                       itself (Sepolia milestone 1)
  src/*.sol            ShieldedPool + NonceManager (EIP-8250) + RecentRoots
                       (EIP-8272) + AttestedVerifier shim; Foundry tests port
                       pool/envelope.py's attack battery on-chain and check
                       ctxFor/computeClaim/tree-root against the prover
                       (Sepolia milestone 3; see contracts/README.md)
wallet/
  wallet.py            tree/indexer + witness builder (reconstructs the tree
                       from LeafAppended events, builds real auth paths)
  gen_smoke.py         real proofs for a transfer + withdraw, verified off-chain
  smoke.sh             end-to-end (in-process EVM): real STARK -> off-chain
                       verify -> on-chain shield/transfer/withdraw (milestone 4)
  deploy_flow.sh       deploy + run the flow against a live node (anvil or
                       Sepolia); attest.sh is the standalone verifying attester
                       (Sepolia milestone 5; see wallet/DEPLOY.md)
docs/                  figures used by the explainer
```

## Run

```
# the whole protocol, in plain Python (self-checking):
python3 pool/demo.py

# the devnet envelope and its attacks (cross-sender double-spend, lifted
# proof, foreign root, transfer+withdraw in one spend), all refused:
python3 pool/envelope.py

# check the circuit source matches the harness:
python3 circuits/spend.py

# the on-chain hash vs vectors exported from leanVM (needs Foundry):
cd contracts && forge test && python3 reference/poseidon16.py

# prove and verify real spends on your machine (leanVM fetched automatically):
cd prover && cargo run --release --bin prove-spend -- --demo 20
# (or the in-leanVM form: apply circuits/pool_circuits.patch, see circuits/README.md)
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
requires four bindings in the pool's on-chain `VERIFY` logic: (1) the sender
equals the pool's single pinned `POOL_SENDER` (EIP-8250 key domains are per
sender, so the pin is what makes the spent set global; any other sender could
double-spend the note); (2) the consumed nonce key set is exactly `[nf]` at
`nonce_seq = 0` (EIP-8250); (3) exactly one recent-root reference carries the
pool's own `source_id` and its root equals the claim's (EIP-8272); (4) exactly
one of `out_cm`, `ctx` is zero (both nonzero would mint). `pool/envelope.py`
runs each binding's attack. Because the nonce key is consumed at payment
approval and survives later-frame reverts, the pool's post-approval frame must
be revert-free (a duplicate append is a no-op), or a note burns.
See [devnet/](devnet/README.md).

Stated residual trust surface: leanVM's current ~124-bit classical / ~62-bit
quantum hash security (so "PQ" is directional, not yet 128-bit); the circuit and
contract are unaudited; the four contract-side bindings above are trusted, not
proven in-circuit; the devnet must itself supply a leanVM proof verifier
(precompile or native, none of the three EIPs provides one) and a funded
payment path for `POOL_SENDER` (the fee story is an open problem, see
devnet/); and this is a research prototype, not production software.

Privacy limits: anonymity equals the number of indistinguishable unspent notes
at spend time, a dynamic set that can be as small as 1 (a spend into a tiny pool
is linkable), so wallets should wait for a sufficient set and avoid
spend-soon-after-deposit timing. Spends all come from the pinned `POOL_SENDER`,
which is what decorrelates users on the sending side; the deposit's funding
address is still on-chain and must be decorrelated by the wallet, and note
commitments travel to recipients out of band (that channel should be PQ
encrypted too). By design there is no compliance or viewing-key mechanism.

## License

Apache-2.0 (see `LICENSE`). The Python model and circuit are original work;
`circuits/pool_circuits.patch` modifies `leanEthereum/leanVM` (Apache-2.0) at
commit `12e6151`; see `NOTICE`.
