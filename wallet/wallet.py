"""Wallet and indexer for the PQ shielded pool.

Reconstructs the note-commitment tree from the pool's `LeafAppended` events
(here: an ordered list of leaves), computes real Merkle authentication paths
that match `ShieldedPool._append`, and builds the spend witnesses the prover
(`prover/`) consumes. The hash is leanVM's Poseidon16, imported from the same
reference the contracts and circuit are checked against, so the root a wallet
computes for a leaf set equals the root the pool publishes for it.

Digest convention throughout: a digest is 8 KoalaBear field elements (a list of
8 ints < p). `hex32` gives the canonical 32-byte encoding used on-chain.
"""
import random
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "contracts" / "reference"))
from poseidon16 import compress_pair, tagged, P  # noqa: E402

DEPTH = 20
ZERO8 = [0] * 8
TAG_PK, TAG_LEAF, TAG_NULL = 1, 2, 3

_RNG = None  # None = cryptographic secrets; set_seed makes note generation reproducible


def set_seed(seed):
    """Make note generation deterministic (for reproducible fixtures/tests)."""
    global _RNG
    _RNG = random.Random(seed)


def rand_digest():
    """A uniformly random valid digest (8 field elements)."""
    if _RNG is None:
        return [secrets.randbelow(P) for _ in range(8)]
    return [_RNG.randrange(P) for _ in range(8)]


def hex32(d):
    return "0x" + "".join(f"{w:08x}" for w in d)


def hashpair(l, r):
    return compress_pair(l, r)


# ---- note cryptography (mirrors circuits/spend.py and pool/note.py) ----

def owner_pk(spend_key):
    return tagged(TAG_PK, spend_key, ZERO8)


def commitment(spend_key, rho):
    return tagged(TAG_LEAF, owner_pk(spend_key), rho)


def nullifier(spend_key, cm):
    return tagged(TAG_NULL, spend_key, cm)


def new_note():
    """Fresh (spend_key, rho); the wallet keeps both secret."""
    return rand_digest(), rand_digest()


# ---- the tree / indexer ----

class Tree:
    """Full zero-padded Merkle tree of note commitments, matching the pool.

    Built from the ordered leaf list an indexer reads off `LeafAppended`
    events. `root()` equals `ShieldedPool.currentRoot()` for the same leaves,
    and `auth_path(idx)` gives the (siblings, bits) the circuit expects
    (bit = idx&1 at each level; bit 0 means the node is the left child).
    """

    def __init__(self, depth=DEPTH):
        self.depth = depth
        self.leaves = []
        self.zeros = [ZERO8]
        for _ in range(depth):
            self.zeros.append(hashpair(self.zeros[-1], self.zeros[-1]))

    def append(self, cm):
        idx = len(self.leaves)
        self.leaves.append(cm)
        return idx

    def _levels(self):
        level = list(self.leaves) if self.leaves else [self.zeros[0]]
        levels = [level]
        for d in range(self.depth):
            nxt = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else self.zeros[d]
                nxt.append(hashpair(left, right))
            level = nxt
            levels.append(level)
        return levels

    def root(self):
        return self._levels()[self.depth][0]

    def auth_path(self, idx):
        levels = self._levels()
        siblings, bits = [], []
        for d in range(self.depth):
            level = levels[d]
            sib_idx = idx ^ 1
            sib = level[sib_idx] if sib_idx < len(level) else self.zeros[d]
            siblings.append(sib)
            bits.append(idx & 1)
            idx >>= 1
        return siblings, bits


# ---- witness building ----

def _ctx_for_recipient(addr_hex):
    """160-bit address as 8 big-endian 20-bit chunks (matches ShieldedPool.ctxFor
    and prover ctx_for_recipient)."""
    h = addr_hex[2:] if addr_hex.startswith("0x") else addr_hex
    val = int(h, 16)
    bits = [(val >> (159 - i)) & 1 for i in range(160)]
    return [sum(bits[c * 20 + k] << (19 - k) for k in range(20)) for c in range(8)]


def build_witness(tree, idx, spend_key, rho, out_cm=None, recipient=None):
    """A spend witness against the current tree.

    Transfer: pass out_cm (the recipient's fresh commitment), no recipient.
    Withdraw: pass recipient (a 0x address); out_cm defaults to zero.
    """
    if (out_cm is None) == (recipient is None):
        raise ValueError("pass exactly one of out_cm (transfer) or recipient (withdraw)")
    siblings, bits = tree.auth_path(idx)
    if recipient is not None:
        out_cm, ctx = ZERO8, _ctx_for_recipient(recipient)
    else:
        ctx = ZERO8
    return {
        "spend_key": spend_key,
        "rho": rho,
        "siblings": siblings,
        "bits": bits,
        "out_cm": out_cm,
        "ctx": ctx,
    }


def spend_nullifier(spend_key, rho):
    return nullifier(spend_key, commitment(spend_key, rho))


def _selfcheck():
    """The wallet tree must agree with the pool's incremental-tree fixture."""
    import json
    fx = json.loads((Path(__file__).parent.parent / "contracts" / "vectors"
                     / "pool_fixtures.json").read_text())["tree"]
    t = Tree()
    assert hex32(t.root()) == fx["root_empty"], "empty root mismatch"

    def unhex(h):
        b = bytes.fromhex(h[2:])
        return [int.from_bytes(b[i:i + 4], "big") for i in range(0, 32, 4)]

    t.append(unhex(fx["cm0"]))
    assert hex32(t.root()) == fx["root_after_cm0"], "root after cm0 mismatch"
    t.append(unhex(fx["cm1"]))
    assert hex32(t.root()) == fx["root_after_cm0_cm1"], "root after cm0,cm1 mismatch"

    # a spent note's nullifier and a rebuilt path reproduce the committed leaf
    sk, rho = new_note()
    cm = commitment(sk, rho)
    t2 = Tree()
    i = t2.append(cm)
    sibs, bits = t2.auth_path(i)
    node = cm
    for b, s in zip(bits, sibs):
        node = hashpair(node, s) if b == 0 else hashpair(s, node)
    assert node == t2.root(), "auth path does not reproduce the root"
    print("wallet.py OK: tree matches the pool fixture; auth paths verify")


if __name__ == "__main__":
    _selfcheck()
