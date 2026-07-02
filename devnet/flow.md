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
  sender     = <shared pool/relayer sender>   # see the privacy note in step 5
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
- **EIP-8250 (protocol)**: every non-zero nonce key must be unused. `nf` is a
  non-zero key, so key-freshness is the spent-once check. If the frame is
  included, `nf` is marked used at the payment-approval step, regardless of
  whether any later frame reverts.
- **The pool contract's VERIFY logic** must bind the proof to this exact
  envelope, or a lifted proof could be replayed under a different key or sender.
  It MUST:
  1. verify the leanVM proof and recompute `claim` from `(root, nf, cm_B, 0)`,
     rejecting on mismatch;
  2. read `(source_id, slot, root)` via `RECENTROOTREFLOAD` and require
     `source_id` to be the pool's own root source and `slot` within the window
     (binding the anchored root to *this* pool, per EIP-8272 Security
     Considerations);
  3. assert the consumed nonce key equals `nf` (`TXPARAM_NONCE_KEY_0 == nf`),
     require `TXPARAM_NONCE_KEY_COUNT == 1`, and authenticate
     `(sender, nonce_keys_hash, nonce_seq == 0)`, per EIP-8250 Security
     Considerations (authenticating one key while others ride along is unsafe);
  4. append `cm_B` to the tree and write the new root to EIP-8272.

The claim binds `(root, nf, out_cm, ctx)`. The envelope bindings (sender, nonce
key, root source) are enforced by the checks above, not carried by the claim, so
eliding the `VERIFY`-frame proof from the signature hash is safe only once the
contract performs them.

## 5. After

The pool's state now contains: one consumed nullifier (`nf`), one new commitment
(`cm_B`), one root write. It does not encode Alice's or Bob's in-pool identity,
the amount (fixed and implicit), or any link between `cm_A` and `cm_B`.

Two on-chain leaks are outside the circuit and must be handled by the wallet:
the **transaction sender** and the **deposit funding address**. Sender
unlinkability holds only when the frame is submitted from a shared pool/relayer
sender (a personal EOA sender links the spend, and for a withdraw links its
`ctx` recipient); this is the motivating use case for EIP-8250's keyed nonces
(concurrent spends from one shared sender). The deposit's funder is on-chain and
must be decorrelated by the wallet.

Privacy also equals the count of indistinguishable unspent notes at spend time.
That set is dynamic and can be 1: a spend into a small or single-deposit pool is
linkable or fully deanonymizing. This trace illustrates the mechanics; it is not
a privacy-preserving scenario on its own. Wallets should wait for a sufficient
anonymity set and avoid spend-soon-after-deposit timing.

Bob now owns the note at its new index and can transfer it onward the same way,
or withdraw: same frame shape with `out_cm = 0` and `ctx = <recipient address>`,
paying one denomination out of the pool.

## What the devnet is testing

That this whole path works using only base-protocol primitives: the proof is a
normal frame, the nullifier is a normal keyed nonce, the root is a normal
recent-root reference. The pool still supplies its own `VERIFY` logic (step 4)
to bind them together. If it works, PQ privacy is an application on top of
8141 / 8250 / 8272, not a special case the protocol has to know about.
