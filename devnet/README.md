# Devnet integration: EIP-8141 + EIP-8250 + EIP-8272

The pool is designed so that its three moving parts map exactly onto three
in-flight EIPs. On a devnet carrying all three, a private transfer is an
ordinary frame transaction, and the protocol enforces the pool's safety rules
for it, no bespoke mempool or precompile required.

| Pool concept | EIP | What the EIP provides |
|---|---|---|
| The spend proof | [EIP-8141](https://github.com/ethereum/EIPs) frame tx (+ [EIP-8288](https://github.com/ethereum/EIPs/pull/11772) aggregation) | The private tx is a frame transaction. The leanVM spend proof rides in a `VERIFY` frame, and the frame's payment-approval step is where consumption becomes atomic. EIP-8288 lets the mempool fold many pool proofs into one recursive STARK. |
| The nullifier | [EIP-8250](https://github.com/ethereum/EIPs) keyed nonces | The nullifier is used as a **non-zero nonce key**, spent at `nonce_seq = 0` (a fresh single-use key's sequence). `MAX_NONCE_KEYS = 16`, and disjoint non-zero key sets are replay-independent, so the protocol's `NONCE_MANAGER` provides an atomic spent-once guarantee: a successful spend marks the key used regardless of later reverts. This becomes the pool's spent set **only if** the pool's `VERIFY` logic binds the consumed key to the proven `nf` and rejects extra keys (see below); otherwise a proof for `nf_A` can ride a frame that consumes a different key. |
| The recent root | [EIP-8272](https://github.com/ethereum/EIPs) recent roots | The pool writes one root per block into the `RECENT_ROOT_ADDRESS` system contract (`msg.sender` becomes the source). Wallets reference a `(source_id, slot, root)` tuple from an earlier slot within the last `RECENT_ROOT_LENGTH - 1 = 8191` slots (a root written in slot S is referenceable from S+1). The pool's `VERIFY` logic must require `source_id` to be the pool's own source, so membership is anchored to *this* pool's tree, not any tree. |

## Why this matters

Two properties fall out of the mapping, and they are the point of running the
devnet:

1. **The pool needs no privileged infrastructure.** The base protocol supplies
   the primitives, spent-once keys and a recent-roots ring, and the pool's own
   `VERIFY` logic binds them to each proof. The contract stays a bare tree plus
   a handful of binding checks; the anti-double-spend and freshness machinery
   lives in EIP-8250 and EIP-8272 where every application can share it.
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
so the pool's `VERIFY` logic must add the envelope bindings itself:

- read `(source_id, slot, root)` via `RECENTROOTREFLOAD` and require
  `source_id == pool_source_id` and `slot` within the window (EIP-8272), so the
  anchored root is this pool's, not a foreign tree's;
- assert `TXPARAM_NONCE_KEY_0 == nf` and `TXPARAM_NONCE_KEY_COUNT == 1`, and
  authenticate `(sender, nonce_keys_hash, nonce_seq == 0)` (EIP-8250 Security
  Considerations), so the consumed key is exactly the proven nullifier and no
  extra keys ride along.

Without these, a valid proof for `nf_A` could be lifted into a frame that
consumes a different key or references a foreign root, and `nf_A` would go
unconsumed, a double-spend at the devnet layer. With them, `nf` becomes the
nonce key (EIP-8250), `root` is bound to the pool's recent-roots source
(EIP-8272), `out_cm` is appended (transfer), and `ctx` names the recipient
(withdraw).

## Devnet test plan

What to stand up and assert end to end (see [flow.md](flow.md) for the
field-by-field trace of one transfer):

1. Deploy the immutable pool contract (tree + root ring writer + no admin).
2. **Shield**: a normal call depositing one denomination and appending a
   commitment; assert the new root lands in `RECENT_ROOT_ADDRESS` for the
   pool's `source_id`.
3. **Private transfer**: submit a frame tx whose `VERIFY` frame carries the
   leanVM proof, with `nonce_keys = [nullifier]`, `nonce_seq = 0`, and a
   `(source_id, slot, root)` reference to a recent root. Assert: the frame is
   admitted; the proof verifies against the recomputed claim; the consumed nonce
   key equals the claim's `nf` and `TXPARAM_NONCE_KEY_COUNT == 1`;
   `(sender, nonce_keys_hash, nonce_seq == 0)` is authenticated; the referenced
   `source_id` is the pool's own; the nullifier key is marked used; and the
   recipient's `out_cm` is appended.
4. **Double-spend**: replay the same nullifier as a nonce key; assert the
   protocol rejects it (key already used).
4b. **Lifted proof**: place a valid proof in a frame whose `nonce_keys` differs
   from the proven `nf`, or from a different sender; assert the pool's `VERIFY`
   bindings reject it (this is the attack the bindings exist to stop).
5. **Stale root**: reference a root older than `RECENT_ROOT_LENGTH - 1 = 8191`
   slots, or one from a foreign `source_id`; assert rejection.
6. **Withdraw**: a frame tx with `out_cm = 0` and `ctx = recipient`; assert one
   denomination is paid out and the nullifier is consumed.
7. **Aggregation (optional, EIP-8288)**: submit several private spends in one
   slot and assert they fold into one recursive STARK the block verifies once.

The reference model in [`../pool/`](../pool/) runs steps 2-6 in plain Python
today (`python3 ../pool/demo.py`); the devnet swaps the Python `spend_relation`
check for the leanVM proof and the in-memory sets for the EIP-8250 / EIP-8272
system contracts.
