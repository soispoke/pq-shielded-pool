# One private transfer, traced through the stack

Alice holds a shielded note and privately sends it to Bob. Here is every field,
from her wallet to the block, on a devnet carrying EIP-8141 / 8250 / 8272.

## Before: Alice has a note

Alice shielded earlier: she deposited one denomination and the pool appended
`cm_A = H(TAG_LEAF, H(TAG_PK, spend_key_A), rho_A)` at index `i`. She kept
`spend_key_A` and `rho_A` secret. The pool wrote the resulting root into
`RECENT_ROOT_ADDRESS`.

## 1. Bob hands Alice a target

Bob generates `spend_key_B, rho_B` and sends Alice only the commitment
`cm_B = H(TAG_LEAF, H(TAG_PK, spend_key_B), rho_B)`. Alice learns nothing about
Bob's secrets; Bob's future ownership is sealed in `cm_B`.

## 2. Alice's wallet builds the proof

The wallet reads a recent `(source_id, slot, root)` from EIP-8272 (any root
from an earlier slot within the last `RECENT_ROOT_LENGTH - 1 = 8191` slots; a
root written in slot S is referenceable from S+1 onward), fetches the
authentication path for index `i`, and proves the spend circuit with:

- private: `spend_key_A`, `rho_A`, the path `siblings` and `bits`;
- output note `out_cm = cm_B`, context `ctx = 0` (a transfer creates no payout).

The circuit computes and exposes one public value:

```
nf    = H(TAG_NULL, spend_key_A, cm_A)            # Alice's nullifier for this note
claim = H(TAG_CLAIM, H(root || nf), H(cm_B || 0)) # the single public output
```

Proving takes ~20-28 ms on an M5 Max (~23 ms at the default depth 32); the proof
is ~155 KiB.

## 3. Alice submits a frame transaction (EIP-8141)

The fields sit at three layers. The EIP-8250 keyed nonce and the EIP-8272 root
reference are transaction-level fields (covered by the signature hash); the
`VERIFY` frame carries only the proof as its data (elided from the signature
hash); the pool call carries `out_cm` and `ctx` as calldata.

```
frame tx
  sender     = POOL_SENDER   # the pool's pinned sender; see step 4 and step 5
  nonce_keys = [ nf ]        # EIP-8250: the nullifier is a non-zero nonce key
  nonce_seq  = 0             # a fresh single-use key's sequence is 0
  recent_root_references = [ (source_id, slot, root) ]   # EIP-8272, tx-level
  frames:
    VERIFY frame
      data = <leanVM STARK>                    # elided from the signature hash
    SENDER/payment frame (calls the pool)
      calldata = (out_cm = cm_B, ctx = 0)
```

`nonce_keys = [nf]` selects the nullifier's own protocol-managed nonce sequence,
which is a separate domain from the sender's legacy account nonce (that domain
is used only when `nonce_keys == [0]`). A fresh nullifier's sequence reads as 0,
so `nonce_seq = 0` is the only includable value; payment approval advances it to
1, permanently consuming the key.

## 4. The protocol and the pool validate, atomically

- **EIP-8272 (protocol)**: the referenced `(source_id, slot, root)` must resolve
  to a root actually written for that source within the window. Stale or absent
  entries are rejected here.
- **EIP-8250 (protocol)**: every non-zero nonce key must be unused *for this
  sender*. Key domains are per sender (`slot(sender, key)`), so freshness of
  `(POOL_SENDER, nf)` is the spent-once check. If the frame is included, the
  key is marked used at the payment-approval step, regardless of whether any
  later frame reverts.
- **The pool contract's VERIFY logic** must bind the proof to this exact
  envelope, or a valid proof could be replayed under a different key or sender.
  It MUST:
  1. verify the leanVM proof and recompute `claim` from `(root, nf, cm_B, 0)`,
     rejecting on mismatch;
  2. require the transaction sender to equal `POOL_SENDER`. Because key
     domains are per sender, this check is what makes the spent set global: a
     frame from any other sender would consume a fresh `(other_sender, nf)`
     slot and double-spend the note, and the protocol alone would accept it;
  3. scan the recent-root references via `RECENTROOTREFLOAD`, require exactly
     one with `source_id` equal to the pool's own root source, and require its
     root to equal the claim's `root` (binding the anchored root to *this*
     pool, per EIP-8272 Security Considerations);
  4. assert the consumed nonce key equals `nf` (`TXPARAM_NONCE_KEY_0 == nf`),
     require `TXPARAM_NONCE_KEY_COUNT == 1` and `nonce_seq == 0`, and reject
     `nf == 0`, per EIP-8250 Security Considerations (authenticating one key
     while others ride along is unsafe);
  5. require exactly one of `out_cm`, `ctx` to be zero (a spend is a transfer
     or a withdraw, never both: accepting both would mint);
  6. append `cm_B` to the tree and write the new root to EIP-8272. If `cm_B`
     is already a leaf, this is a no-op success, never a revert: `nf` was
     consumed at payment approval and survives later-frame reverts, so a
     revert here would burn the note, and `cm_B` is front-runnable from
     mempool calldata.

The claim binds `(root, nf, out_cm, ctx)`. The envelope bindings (pinned
sender, nonce key, root source, operation shape) are enforced by the checks
above, not carried by the claim, so eliding the `VERIFY`-frame proof from the
signature hash is safe only once the contract performs them. `pool/envelope.py`
runs this checklist, and each check's attack, in plain Python.

## 5. After

The pool's state now contains: one consumed nullifier (`nf`), one new commitment
(`cm_B`), one root write. It does not encode Alice's or Bob's in-pool identity,
the amount (fixed and implicit), or any link between `cm_A` and `cm_B`.

Every spend is submitted from `POOL_SENDER`. That pin is first a soundness
requirement (step 4, check 2), and it delivers sender unlinkability as a side
effect: no personal address ever appears as the sender of a spend. It is also
the motivating use case for EIP-8250's keyed nonces, since disjoint nullifier
keys let one sender carry many users' concurrent spends. One on-chain leak
remains outside the circuit: the **deposit funding address**, which the wallet
must decorrelate. Wallets should also pick their `(slot, root)` reference by a
fixed convention (the newest root at least k slots old); an unusual choice
fingerprints the wallet.

Privacy also equals the count of indistinguishable unspent notes at spend time.
That set is dynamic and can be 1: a spend into a small or single-deposit pool is
linkable or fully deanonymizing. This trace illustrates the mechanics; it is not
a privacy-preserving scenario on its own. Wallets should wait for a sufficient
anonymity set and avoid spend-soon-after-deposit timing.

Bob now owns the note at its new index and can transfer it onward the same way,
or withdraw: same frame shape with `out_cm = 0` and `ctx = <recipient address>`,
paying one denomination out of the pool.

## What the devnet is testing

That this whole path works using base-protocol primitives plus exactly one
devnet-supplied ingredient: the proof is a normal frame, the nullifier is a
normal keyed nonce, the root is a normal recent-root reference, and the only
thing the three EIPs do not provide is the leanVM proof verifier itself (see
[README](README.md#what-the-devnet-must-add)). The pool still supplies its own
`VERIFY` logic (step 4) to bind proof and envelope together. If it works, PQ
privacy is an application on top of 8141 / 8250 / 8272, not a special case the
protocol has to know about.
