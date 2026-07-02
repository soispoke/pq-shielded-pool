"""Note, commitment, nullifier, and the spend relation for the PQ shielded pool.

This module is field-for-field identical to the leanVM spend circuit
(`circuits/spend.py`), with one substitution: the circuit hashes with Poseidon2
over KoalaBear (the post-quantum, STARK-friendly hash), while this reference
model uses SHA-256 as a stand-in so the whole protocol runs in plain Python. On
a real devnet both sides use Poseidon2; only the hash primitive differs, not the
structure, the domain tags, or the relation.

A note is a fixed-denomination coin. It has no value field on purpose: fixed
denomination removes all in-circuit balance arithmetic and range checks, which
is the largest soundness footgun in a 31-bit field. Ownership is knowledge of
`spend_key`; `rho` is a per-note secret that makes each commitment unique.
"""
import hashlib
import secrets

DIGEST = 32                       # bytes per digest (sha256 stand-in)
ZERO = bytes(DIGEST)

# Domain tags: every hash role gets a distinct tag so a digest produced for one
# role can never be reinterpreted as another (caveat 3: domain separation).
TAG_PK, TAG_LEAF, TAG_NULL, TAG_CLAIM = 1, 2, 3, 4


def _h(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def tagged(tag: int, a: bytes, b: bytes) -> bytes:
    """Domain-separated two-input hash: H(tag_block || H(a || b)).

    Mirrors the circuit's `tagged()`: inner = compress(a||b), then compress the
    tag block (tag in the first slot, rest zero) with the inner digest.
    """
    inner = _h(a, b)
    return _h(tag.to_bytes(DIGEST, "big"), inner)


def owner_pk(spend_key: bytes) -> bytes:
    return tagged(TAG_PK, spend_key, ZERO)


def commitment(spend_key: bytes, rho: bytes) -> bytes:
    """The note commitment (a leaf of the pool's Merkle tree)."""
    return tagged(TAG_LEAF, owner_pk(spend_key), rho)


def nullifier(spend_key: bytes, cm: bytes) -> bytes:
    """Key-bound and note-bound: deterministic per note, computable only by the
    owner. Spending the same note twice yields the same nullifier, which the
    pool's spent set rejects (caveats 4 and 5)."""
    return tagged(TAG_NULL, spend_key, cm)


def claim(root: bytes, nf: bytes, out_cm: bytes, ctx: bytes) -> bytes:
    """The single public value the proof exposes and the contract recomputes.

    Binds the anchored root, the nullifier, the output note, and the context
    (withdraw recipient, or zero for a transfer) into one digest. This is the
    EIP-8288 `data_hash` label the contract checks the proof against.
    """
    c1 = _h(root, nf)
    c2 = _h(out_cm, ctx)
    return tagged(TAG_CLAIM, c1, c2)


def new_note():
    """Fresh (spend_key, rho); the wallet keeps both secret."""
    return secrets.token_bytes(DIGEST), secrets.token_bytes(DIGEST)


def spend_relation(claim_pub, root, nf, out_cm, ctx, spend_key, rho, siblings, bits):
    """The same statement the leanVM circuit proves, re-expressed in Python.

    On a real devnet the leanVM proof establishes this while hiding
    (spend_key, rho, siblings, bits), and exposes only the single public value
    `claim_pub`; the contract recomputes the claim from the on-chain publics and
    the write-once public input forces the circuit's computed claim to equal it.
    Here we run the relation in the clear (SHA-256 stand-in) so the reference
    pool can validate a spend without a prover. Returns True iff the opening is
    valid and binds to `claim_pub`.
    """
    # caveat 1: path bits must be boolean
    if any(b not in (0, 1) for b in bits):
        return False
    cm = commitment(spend_key, rho)
    # walk the authentication path (internal nodes: plain two-input hash; leaf vs
    # internal-node separation comes from the fixed-depth walk plus second-
    # preimage resistance, not from a per-node tag)
    node = cm
    for b, sib in zip(bits, siblings):
        node = _h(node, sib) if b == 0 else _h(sib, node)
    # caveat 2: the computed root must equal the anchored root
    if node != root:
        return False
    # caveats 4/5: the nullifier must be the note's key-bound nullifier
    if nf != nullifier(spend_key, cm):
        return False
    # bind the opening to the public claim (this is the write-once public-input
    # binding, modeled as a recompute-and-compare against the submitted claim)
    return claim(root, nf, out_cm, ctx) == claim_pub
