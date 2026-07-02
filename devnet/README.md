# Devnet integration: EIP-8141 + EIP-8250 + EIP-8272

The pool is designed so that its three moving parts map exactly onto three
in-flight EIPs. On a devnet carrying all three, a private transfer is an
ordinary frame transaction, and the protocol enforces the pool's spent-once
and root-freshness rules. One thing the three EIPs do not supply is a way to
verify the leanVM proof on chain; the devnet must add that itself (see
[What the devnet must add](#what-the-devnet-must-add)).

| Pool concept | EIP | What the EIP provides |
|---|---|---|
| The spend proof | [EIP-8141](https://github.com/ethereum/EIPs) frame tx (+ [EIP-8288](https://github.com/ethereum/EIPs/pull/11772) aggregation) | The private tx is a frame transaction. The leanVM spend proof rides in a `VERIFY` frame, and the frame's payment-approval step is where consumption becomes atomic. EIP-8288 lets the mempool fold many pool proofs into one recursive STARK. |
| The nullifier | [EIP-8250](https://github.com/ethereum/EIPs) keyed nonces | The nullifier is used as a **non-zero nonce key**, spent at `nonce_seq = 0` (a fresh single-use key's sequence). `MAX_NONCE_KEYS = 16`, and disjoint non-zero key sets are replay-independent, so the protocol's `NONCE_MANAGER` provides an atomic spent-once guarantee: a successful spend marks the key used regardless of later reverts. This becomes the pool's spent set **only if** the pool's `VERIFY` logic binds the consumed key to the proven `nf`, rejects extra keys, **and pins the sender**. Keyed-nonce domains are per sender (`slot(sender, key)`; EIP-8250 scopes replay protection to `(sender, nonce_keys, nonce_seq)`), so the same `nf` is a fresh key under every other sender: without the pin, one note is spendable once per sender. `(POOL_SENDER, nf)` is the spent set (see below). |
| The recent root | [EIP-8272](https://github.com/ethereum/EIPs) recent roots | The pool writes one root per block into the `RECENT_ROOT_ADDRESS` system contract (`msg.sender` becomes the source). Wallets reference a `(source_id, slot, root)` tuple from an earlier slot within the last `RECENT_ROOT_LENGTH - 1 = 8191` slots (a root written in slot S is referenceable from S+1). The pool's `VERIFY` logic must require `source_id` to be the pool's own source, so membership is anchored to *this* pool's tree, not any tree. |

## Why this matters

Two properties fall out of the mapping, and they are the point of running the
devnet:

1. **The pool needs no privileged infrastructure.** The base protocol supplies
   the primitives, spent-once keys and a recent-roots ring, and the pool's own
   `VERIFY` logic binds them to each proof. The contract stays a bare tree plus
   a handful of binding checks; the anti-double-spend and freshness machinery
   lives in EIP-8250 and EIP-8272 where every application can share it. (The
   proof verifier itself is the exception: see
   [What the devnet must add](#what-the-devnet-must-add).)
2. **Private transactions get first-class mempool treatment.** Because the
   nullifier is the nonce key, keyed-aware mempools can admit concurrent
   private spends from the same account (disjoint key sets are
   replay-independent), and EIP-8288 can aggregate the proofs, so PQ privacy
   rides the same bandwidth path as the [recursive STARK mempool](https://github.com/soispoke/recursive-stark-mempool).

## The claim binding

leanVM exposes one 8-cell public input. The circuit writes
`claim = H(TAG_CLAIM, H(root || nf), H(out_cm || ctx))` there, and the pool
contract recomputes the same digest from the on-chain `(root, nf, out_cm, ctx)`
before accepting the frame. This is the EIP-8288 `data_hash` label pattern: the
proof is meaningful only because the contract pins the exact statement it
accepts.

The claim binds `(root, nf, out_cm, ctx)` but **not** the transaction envelope,
so the pool's `VERIFY` logic must add the envelope bindings itself. All four
are MUSTs; `pool/envelope.py` runs each one's attack:

- **Pinned sender**: require the transaction sender to equal the pool's single
  `POOL_SENDER`. EIP-8250 key domains are per sender, so this is what makes
  `(POOL_SENDER, nf)` a global spent set; a frame from any other sender would
  consume a fresh `(other_sender, nf)` slot and double-spend the note. The
  natural instantiation is the pool's own EIP-8141 account, whose authorization
  is this `VERIFY` frame itself, which also removes any relayer-signature
  bottleneck. This makes the pinned sender part of the trust surface: its
  liveness and censorship properties are the pool's.
- **Key set**: assert `TXPARAM_NONCE_KEY_0 == nf`, `TXPARAM_NONCE_KEY_COUNT == 1`,
  and `nonce_seq == 0`, and reject `nf == 0` (EIP-8250 Security
  Considerations), so the consumed key is exactly the proven nullifier and no
  extra keys ride along.
- **Root reference**: scan the transaction's recent-root references via
  `RECENTROOTREFLOAD`, require exactly one with `source_id == pool_source_id`,
  and require its `root` to equal the root bound in the claim (EIP-8272
  Security Considerations), so the anchored root is this pool's, not a foreign
  tree's. (Requiring exactly one pool reference keeps selection unambiguous;
  the other 15 slots stay free for unrelated applications.)
- **Operation shape**: require exactly one of `out_cm`, `ctx` to be zero. The
  circuit deliberately accepts any pair, so a contract that accepted both
  nonzero would, for one nullifier, both append a note and pay out a
  denomination: value creation.

Without these, a valid proof for `nf_A` could be lifted into a frame that
consumes a different key, be replayed under a different sender, or reference a
foreign root, and each is a double-spend (or a mint) at the devnet layer. With
them, `nf` becomes the nonce key (EIP-8250), `root` is bound to the pool's
recent-roots source (EIP-8272), `out_cm` is appended (transfer), and `ctx`
names the recipient (withdraw).

Cross-instance replay (the same proof against another pool or chain whose tree
happens to match) can only donate, never steal, and the source binding excludes
it; a deployment wanting defense in depth can also fold the pool address into
`ctx` on withdraws, per EIP-8272's advice to bind the chain domain outside the
tuple.

### Encodings

Contract-side checks compare protocol words against circuit digests, so the
packing must be canonical: a digest is 8 KoalaBear field elements, packed as
8 big-endian 32-bit words (each element is < 2^31, so the top bit of every
word is zero) into one 32-byte value. That value is the `uint256` nonce key
for `nf`, the `bytes32` root written to EIP-8272, and the byte string the
contract hashes when recomputing the claim. Two implementations that disagree
here fail closed (claims will not match), but the rule still belongs in one
place.

## What the devnet must add

The three EIPs supply envelope machinery only; two ingredients come from the
devnet itself.

1. **A leanVM proof verifier.** Verifying a WHIR/Poseidon2-over-KoalaBear
   STARK in EVM bytecode is not realistic (no matching precompiles exist, and
   even a 256-byte Groth16 verify costs ~205k gas via precompiles), so the
   devnet must ship a leanVM-verify precompile or verify `VERIFY`-frame proofs
   natively. The proof is also big: ~155 KiB of transaction data is roughly
   6M gas of EIP-7623 data floor per spend, so a gas and mempool policy for
   transactions of this size comes with it. (Native verification is ~16-18 ms
   on an M5 Max; aggregation amortizes both costs but is out of scope here.)
2. **Fees and payment (open problem).** Someone must pass EIP-8141 payment
   approval for each spend, and nothing here compensates them: the claim binds
   no fee and no relayer, and fixed denomination forecloses fee skimming. The
   pinned `POOL_SENDER` needs a funded payment path; candidate directions are
   a shield-time surcharge that funds it, an extended `ctx` binding
   `(relayer, fee)` on withdraws, or out-of-band payment with its own linkage
   risks. This prototype deliberately leaves the choice open; a deployment
   cannot.

## Post-approval reverts burn notes

EIP-8250 consumes the nonce key at payment approval, and consumption "MUST NOT
be reverted by a later frame revert." The pool's state changes necessarily live
in a later frame (`VERIFY` frames are static), so any revert there consumes
`nf` while appending nothing: the note is destroyed. The pool-call frame must
therefore be revert-free. Two rules follow:

- a duplicate `out_cm` append is a no-op success, never a revert: `out_cm` is
  visible in mempool calldata, so a revert would let an attacker front-run
  `shield(out_cm)` to burn the spent note (see `pool/pool.py` and step 7 of
  `pool/demo.py`; the no-op reaches the same end state);
- wallets and the sender pipeline must budget the pool frame's gas generously
  and treat an under-gassed frame as note loss, per EIP-8250's "minimize
  post-approval revert paths."

## Events and wallet sync

The contract must emit what wallets need to reconstruct the tree and find
their notes: an event per append with `(cm, leaf_index)`, and the root written
per state-changing call (the EIP-8272 write is storage, not a log). Recipients
learn their commitment out of band when the sender requests it; that channel
is outside the protocol, and if it is not post-quantum encrypted (e.g.
ML-KEM), it is the one non-PQ hop left in the story. Wallets should also
standardize which recent root they reference (e.g. the newest root at least a
fixed number of slots old): an unusual `(slot, root)` choice fingerprints the
wallet and partitions the anonymity set.

## Devnet test plan

What to stand up and assert end to end (see [flow.md](flow.md) for the
field-by-field trace of one transfer):

1. Deploy the immutable pool contract (tree + root ring writer + no admin) and
   its pinned `POOL_SENDER` account.
2. **Shield**: a normal call depositing one denomination and appending a
   commitment; assert the new root lands in `RECENT_ROOT_ADDRESS` for the
   pool's `source_id`, and that the `(cm, leaf_index)` event is emitted.
3. **Private transfer**: submit a frame tx from `POOL_SENDER` whose `VERIFY`
   frame carries the leanVM proof, with `nonce_keys = [nullifier]`,
   `nonce_seq = 0`, and a `(source_id, slot, root)` reference to a recent root.
   Assert: the frame is admitted; the proof verifies against the recomputed
   claim; the consumed nonce key equals the claim's `nf` and
   `TXPARAM_NONCE_KEY_COUNT == 1`; the sender equals `POOL_SENDER`; the
   referenced `source_id` is the pool's own and its root equals the claim's;
   the nullifier key is marked used; and the recipient's `out_cm` is appended.
4. **Double-spend, same sender**: replay the same nullifier as a nonce key
   from `POOL_SENDER`; assert the protocol rejects it (key already used).
4b. **Double-spend, cross-sender**: replay the same spend from a different
   sender. The protocol alone accepts this (per-sender key domains make
   `(other_sender, nf)` fresh); assert the pool's pinned-sender check rejects
   it. This is the primary adversarial case for the whole mapping.
4c. **Lifted proof**: place a valid proof in a frame whose `nonce_keys`
   differs from the proven `nf`, or carries extra keys; assert the pool's
   `VERIFY` bindings reject it.
5. **Stale root**: reference a root older than `RECENT_ROOT_LENGTH - 1 = 8191`
   slots, or one from a foreign `source_id`; assert rejection.
6. **Withdraw**: a frame tx with `out_cm = 0` and `ctx = recipient`; assert one
   denomination is paid out and the nullifier is consumed.
6b. **Operation shape**: submit a valid proof with both `out_cm` and `ctx`
   nonzero; assert rejection (accepting it would mint).
6c. **Duplicate output**: shield `out_cm` first, then submit a transfer
   creating the same `out_cm`; assert the append is a no-op success, the
   nullifier is consumed, and nothing reverts.
7. **Aggregation (optional, EIP-8288)**: submit several private spends in one
   slot and assert they fold into one recursive STARK the block verifies once.

The reference model in [`../pool/`](../pool/) runs the application half in
plain Python today (`python3 ../pool/demo.py`), and
`python3 ../pool/envelope.py` runs the envelope half (steps 3-6b against a
model of the per-sender `NONCE_MANAGER` and the windowed recent roots); the
devnet swaps the Python `spend_relation` check for the leanVM proof and the
in-memory models for the EIP-8250 / EIP-8272 system contracts.
