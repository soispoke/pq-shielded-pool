"""Wallet and indexer for the BN254 join-split shielded pool.

Value-carrying notes: cm = Poseidon(TAG_LEAF, inner, value) with
inner = Poseidon2(owner_pk, rho). A recipient reveals only `inner` (never the
secrets); the payer chooses the value, and `shield` hashes msg.value into the
commitment on-chain, so a deposit's value is what was actually deposited.

A spend consumes two inputs (a zero-value dummy stands in when only one real
note is spent) and creates two outputs. `build_witness` returns the circom
input map that ../tooling proves with snarkjs against build/spend_final.zkey.
"""
import random
import secrets
import sys
from pathlib import Path

from eth_hash.auto import keccak

sys.path.insert(0, str(Path(__file__).parent.parent / "reference"))
from poseidon_bn254 import P, p2, tagged, TAG_PK, TAG_LEAF, TAG_NULL  # noqa: E402

DEPTH = 20
MAX_VALUE = 1 << 128
DOMAIN_TAG = bytes.fromhex("40752e102d2a749c61d42a71e297edd3b493de639003b9480a700d589d98065b")

_RNG = None  # None = cryptographic secrets; set_seed makes note generation reproducible


def set_seed(seed):
    """Make note generation deterministic (for reproducible fixtures/tests)."""
    global _RNG
    _RNG = random.Random(seed)


def rand_fe():
    """A uniformly random field element."""
    if _RNG is None:
        return secrets.randbelow(P)
    return _RNG.randrange(P)


# ---- note cryptography (mirrors ../circuits/spend.circom) ----

def owner_pk(spend_key):
    return tagged(TAG_PK, spend_key, 0)


def inner(spend_key, rho):
    """What a recipient reveals to be paid: hides owner_pk and rho."""
    return p2(owner_pk(spend_key), rho)


def commitment(spend_key, rho, value):
    return tagged(TAG_LEAF, inner(spend_key, rho), value)


def domain_scalar(chain_id, source_id):
    """keccak256(DOMAIN_TAG || uint256_be(chain_id) || source_id) mod Fr."""
    if isinstance(source_id, str):
        source_id = bytes.fromhex(source_id.removeprefix("0x"))
    if len(source_id) != 32 or not 0 <= chain_id < 1 << 256:
        raise ValueError("domain inputs must be uint256 chain_id and bytes32 source_id")
    return int.from_bytes(keccak(DOMAIN_TAG + chain_id.to_bytes(32, "big") + source_id), "big") % P


def nullifier(domain, spend_key, cm):
    return tagged(TAG_NULL, p2(domain, spend_key), cm)


def new_note():
    """Fresh (spend_key, rho); the wallet keeps both secret."""
    return rand_fe(), rand_fe()


def dummy_input():
    """A zero-value dummy input: fabricated secrets, never in the tree. Its
    nullifier derives from its own fabricated cm, so it cannot collide with a
    real note's, and it contributes zero to conservation."""
    sk, rho = new_note()
    return {"sk": sk, "rho": rho, "value": 0, "idx": None}


# ---- the tree / indexer ----

class Tree:
    """Full zero-padded Merkle tree of note commitments, matching the pool."""

    def __init__(self, depth=DEPTH):
        self.depth = depth
        self.leaves = []
        self.zeros = [0]
        for _ in range(depth):
            self.zeros.append(p2(self.zeros[-1], self.zeros[-1]))

    def append(self, cm):
        idx = len(self.leaves)
        assert idx < (1 << self.depth), "tree full"
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
                nxt.append(p2(left, right))
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

def ctx_for_recipient(addr_hex):
    """The recipient address as one field element (matches ShieldedPool.ctxFor)."""
    h = addr_hex[2:] if addr_hex.startswith("0x") else addr_hex
    return int(h, 16)


def build_witness(tree, inputs, outputs, domain, public_amount=0, fee=0, recipient=None):
    """A join-split witness against the current tree, as the circom input map.

    inputs: exactly two dicts {sk, rho, value, idx} (idx None for a dummy,
            which must have value 0). Use dummy_input() to pad.
    outputs: exactly two (inner, value) pairs.
    Values must conserve: sum(in) == sum(out) + public_amount + fee.
    """
    assert len(inputs) == 2 and len(outputs) == 2
    assert all(i["idx"] is not None or i["value"] == 0 for i in inputs), \
        "a dummy input must have value 0"
    total_in = sum(i["value"] for i in inputs)
    total_out = sum(v for _, v in outputs) + public_amount + fee
    assert total_in == total_out, f"not conserved: {total_in} != {total_out}"
    assert all(0 <= v < MAX_VALUE for v in
               [public_amount, fee] + [i["value"] for i in inputs] + [v for _, v in outputs])

    ctx = ctx_for_recipient(recipient) if recipient is not None else 0
    sibs, bits = [], []
    for i in inputs:
        if i["idx"] is None:
            sibs.append([0] * tree.depth)
            bits.append([0] * tree.depth)
        else:
            s, b = tree.auth_path(i["idx"])
            sibs.append(s)
            bits.append(b)
    return {
        "root": str(tree.root()),
        "domain": str(domain),
        "in_spend_key": [str(i["sk"]) for i in inputs],
        "in_rho": [str(i["rho"]) for i in inputs],
        "in_value": [str(i["value"]) for i in inputs],
        "in_siblings": [[str(x) for x in s] for s in sibs],
        "in_bits": [[str(x) for x in b] for b in bits],
        "out_inner": [str(inn) for inn, _ in outputs],
        "out_value": [str(v) for _, v in outputs],
        "public_amount": str(public_amount),
        "fee": str(fee),
        "ctx": str(ctx),
    }


def input_nullifiers(domain, inputs):
    """The two nullifiers a witness's inputs expose, in order."""
    return [nullifier(domain, i["sk"], commitment(i["sk"], i["rho"], i["value"])) for i in inputs]


def output_commitments(outputs):
    return [tagged(TAG_LEAF, inn, v) for inn, v in outputs]


def _selfcheck():
    """The wallet tree must agree with the exported incremental-tree fixture,
    and a value note's auth path must reproduce the root."""
    import json
    fx = json.loads((Path(__file__).parent.parent / "vectors"
                     / "poseidon_bn254_vectors.json").read_text())["tree"]
    t = Tree()
    assert t.root() == int(fx["root_empty"]), "empty root mismatch"
    t.append(int(fx["cm0"]))
    assert t.root() == int(fx["root_after_cm0"]), "root after cm0 mismatch"
    t.append(int(fx["cm1"]))
    assert t.root() == int(fx["root_after_cm0_cm1"]), "root after cm0,cm1 mismatch"

    sk, rho = new_note()
    cm = commitment(sk, rho, 10**18)
    t2 = Tree()
    i = t2.append(cm)
    sibs, bits = t2.auth_path(i)
    node = cm
    for b, s in zip(bits, sibs):
        node = p2(node, s) if b == 0 else p2(s, node)
    assert node == t2.root(), "auth path does not reproduce the root"
    print("wallet.py OK: tree matches the exported fixture; value-note paths verify")


if __name__ == "__main__":
    _selfcheck()
