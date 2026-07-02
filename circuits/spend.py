"""PQ shielded-pool spend circuit (leanVM zkDSL source).

One circuit covers both operations: a private transfer (create a new note for a
recipient) and a withdraw (pay a public recipient). It is compiled to leanVM
bytecode, proved at WHIR rate 1/2, and verified by the harness
`pool_spend_circuits` in `pool_circuits.patch`. The string below is
byte-identical to the one embedded in the patch; `python3 spend.py` checks it
has not drifted.

What it proves (hiding spend_key, rho, and the Merkle path):

    I own a note committed in the pool's tree at the anchored root, and I
    expose exactly one nullifier for it, one optional output note, and one
    context, bound together in a single public claim.

Fixed-denomination notes: there is no value field, so there is no in-circuit
balance arithmetic and no range check to get wrong. Ownership is knowledge of
spend_key.

Witness layout (flat array `w`, DIGEST_LEN = 8 field elements per digest,
DEPTH = tree depth):
    spend_key (8) | rho (8) | siblings (8*DEPTH) | bits (DEPTH) | out_cm (8) | ctx (8)

Public output (written to the 8-cell public-input region at address 0):
    claim = H(TAG_CLAIM, H(root || nf), H(out_cm || ctx))
The immutable contract recomputes this from the on-chain (root, nf, out_cm,
ctx) and rejects the transaction unless it matches (the EIP-8288 data_hash
label pattern).

The five soundness properties, each enforced here rather than assumed:
  1. Path bits are boolean-constrained: assert bits[i]*(bits[i]-1)==0, so each
     bit genuinely selects left/right and the path is well-formed.
  2. Root anchoring: the root is computed from the witness and folded into the
     public claim; the contract checks that root against its recent-roots ring,
     so the prover cannot invent a tree.
  3. Domain separation: owner_pk, leaf, nullifier, and claim each hash under a
     distinct tag (tagged()), so no digest can be reinterpreted across those
     four roles. Internal Merkle nodes use the untagged two-input compression;
     leaf-vs-internal-node confusion is prevented by the fixed-depth path walk
     and second-preimage resistance, not by a per-node tag.
  4. Nullifier binding: nf = H(TAG_NULL, spend_key, cm) is key-bound and
     note-bound (cm is unique via rho), so it is deterministic per note and only
     the owner can produce it.
  5. Double-spend prevention: nf is a public output; the contract maintains a
     spent set (one key per nullifier, the EIP-8250 keyed-nonce shape).

The claim binds only `(root, nf, out_cm, ctx)`. It does NOT bind the transaction
envelope, so end-to-end devnet soundness additionally requires four bindings in
the pool's on-chain VERIFY logic: (a) the sender equals the pool's single
pinned POOL_SENDER (EIP-8250 key domains are per sender, so without the pin the
same nf is a fresh key under every other sender and the note double-spends);
(b) the consumed nonce key set is exactly [nf] at nonce_seq == 0 (EIP-8250
Security Considerations); (c) exactly one recent-root reference carries the
pool's own source_id and its root equals the claim's (EIP-8272 Security
Considerations); (d) exactly one of out_cm, ctx is zero (the circuit accepts
any pair; a contract accepting both nonzero would mint). Without those
out-of-circuit checks a valid proof could be lifted into a different frame or
replayed under a different sender. See `devnet/README.md` and
`pool/envelope.py`, which runs each binding's attack.

Residual trust surface (stated, not hidden): leanVM's hash-based security is
~124-bit classical / ~62-bit quantum today, so "post-quantum" is directional,
not yet 128-bit; the circuit is not audited; the devnet envelope bindings
above are a required part of the trusted contract, not proven in-circuit; and
the devnet must supply the proof verifier itself (none of EIP-8141/8250/8272
provides one).
"""

SPEND_PROGRAM = """
from snark_lib import *
DIGEST_LEN = 8
DEPTH = DEPTH_PLACEHOLDER
TAG_PK = 1
TAG_LEAF = 2
TAG_NULL = 3
TAG_CLAIM = 4

def tagged(tag, a, b, out):
    inner = Array(DIGEST_LEN)
    poseidon16_compress_half(a, b, inner)
    tb = Array(DIGEST_LEN)
    tb[0] = tag
    for i in unroll(1, DIGEST_LEN):
        tb[i] = 0
    poseidon16_compress_half(tb, inner, out)
    return

def main():
    pub = 0
    W = 32 + 9 * DEPTH
    w = Array(W)
    hint_witness("w", w)
    spend_key = w
    rho = w + DIGEST_LEN
    siblings = w + 2 * DIGEST_LEN
    bits = w + (2 + DEPTH) * DIGEST_LEN
    out_cm = w + (2 + DEPTH) * DIGEST_LEN + DEPTH
    ctx = out_cm + DIGEST_LEN

    zero8 = Array(DIGEST_LEN)
    for i in unroll(0, DIGEST_LEN):
        zero8[i] = 0

    for i in unroll(0, DEPTH):
        assert bits[i] * (bits[i] - 1) == 0

    owner_pk = Array(DIGEST_LEN)
    tagged(TAG_PK, spend_key, zero8, owner_pk)

    cm = Array(DIGEST_LEN)
    tagged(TAG_LEAF, owner_pk, rho, cm)

    scratch = Array(DEPTH * DIGEST_LEN)
    state: Mut = cm
    for i in unroll(0, DEPTH):
        out = scratch + i * DIGEST_LEN
        sib = siblings + i * DIGEST_LEN
        if bits[i] == 0:
            poseidon16_compress_half(state, sib, out)
        else:
            poseidon16_compress_half(sib, state, out)
        state = out
    root = state

    nf = Array(DIGEST_LEN)
    tagged(TAG_NULL, spend_key, cm, nf)

    c1 = Array(DIGEST_LEN)
    poseidon16_compress_half(root, nf, c1)
    c2 = Array(DIGEST_LEN)
    poseidon16_compress_half(out_cm, ctx, c2)
    tagged(TAG_CLAIM, c1, c2, pub)
    return
"""


if __name__ == "__main__":
    # drift guard: the string above must stay byte-identical to the circuit
    # embedded in pool_circuits.patch (the one actually proved and verified)
    from pathlib import Path
    patch = (Path(__file__).parent / "pool_circuits.patch").read_text()
    added = [ln[1:] for ln in patch.splitlines()
             if ln.startswith("+") and not ln.startswith("+++")]
    start = added.index('const POOL_SPEND_PROGRAM: &str = r#"')
    end = added.index('"#;', start)
    embedded = "\n" + "\n".join(added[start + 1:end]) + "\n"
    assert embedded == SPEND_PROGRAM, "SPEND_PROGRAM drifted from pool_circuits.patch"
    print("SPEND_PROGRAM matches pool_circuits.patch (byte-identical)")
