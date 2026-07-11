"""Reference implementation of circomlib's Poseidon over BN254 in plain Python.

This is the hash the BN254 spend circuit uses: Poseidon over the BN254 scalar
field, x^5 S-box, 8 full rounds plus 57 (t=3) or 56 (t=4) partial rounds,
state initialised as [0, in_0, ..., in_{n-1}], output state[0]. Constants and
the mix convention (new_state[i] = sum_j M[i][j] * state[j]) are exactly
circomlibjs's poseidon_reference.js; both live in
poseidon_bn254_constants.json, exported by ../tooling/export_vectors.js from
the same circomlibjs package the circuit's poseidon.circom pairs with.

`python3 poseidon_bn254.py` checks every vector in
../vectors/poseidon_bn254_vectors.json (computed by two independent
circomlibjs implementations and asserted equal at export), including the
pool's tagged owner_pk / cm / domain-separated nf / out_cm chain and the depth-20
incremental-tree fixtures. This file is the wallet-side building block and
the source the Solidity library is checked against.
"""
import json
from pathlib import Path

_C = json.loads((Path(__file__).parent / "poseidon_bn254_constants.json").read_text())
P = int(_C["prime"])  # BN254 scalar field


def _params(t):
    c = _C[f"t{t}"]
    return int(c["rounds_f"]), int(c["rounds_p"]), \
        [int(x) for x in c["C"]], [[int(x) for x in row] for row in c["M"]]


_PARAMS = {3: _params(3), 4: _params(4)}


def poseidon(inputs):
    """circomlib Poseidon: 2 or 3 field-element inputs, one output."""
    t = len(inputs) + 1
    rf, rp, C, M = _PARAMS[t]
    state = [0] + [x % P for x in inputs]
    for r in range(rf + rp):
        state = [(x + C[r * t + i]) % P for i, x in enumerate(state)]
        if r < rf // 2 or r >= rf // 2 + rp:
            state = [pow(x, 5, P) for x in state]
        else:
            state[0] = pow(state[0], 5, P)
        state = [sum(M[i][j] * state[j] for j in range(t)) % P for i in range(t)]
    return state[0]


# ---- the pool's tagged-hash shapes (mirrors ../circuits/spend.circom) ----
TAG_PK, TAG_LEAF, TAG_NULL = 1, 2, 3


def p2(a, b):
    return poseidon([a, b])


def p3(a, b, c):
    return poseidon([a, b, c])


def tagged(tag, a, b):
    return poseidon([tag, a, b])


def hex32(x):
    """Canonical bytes32 encoding: one big-endian field element."""
    return "0x" + x.to_bytes(32, "big").hex()


def _check():
    vecs = json.loads((Path(__file__).parent.parent / "vectors" /
                       "poseidon_bn254_vectors.json").read_text())
    for v in vecs["poseidon2"]:
        assert poseidon([int(x) for x in v["in"]]) == int(v["out"]), "poseidon2 mismatch"
    for v in vecs["poseidon3"]:
        assert poseidon([int(x) for x in v["in"]]) == int(v["out"]), "poseidon3 mismatch"

    c = {k: int(v) for k, v in vecs["pool_chain"].items()}
    owner_pk = tagged(TAG_PK, c["spend_key"], 0)
    assert owner_pk == c["owner_pk"], "owner_pk mismatch"
    inner = p2(owner_pk, c["rho"])
    assert inner == c["inner"], "inner mismatch"
    cm = tagged(TAG_LEAF, inner, c["value"])
    assert cm == c["cm"], "cm mismatch"
    # v2 nullifiers are domain-separated (mirrors circuits/spend.circom):
    # nf = Poseidon(TAG_NULL, Poseidon2(domain, spend_key), cm)
    domain_key = p2(c["domain"], c["spend_key"])
    nf = tagged(TAG_NULL, domain_key, cm)
    assert nf == c["nf"], "nf mismatch"
    nf2 = tagged(TAG_NULL, domain_key, tagged(TAG_LEAF, inner, 0))
    assert nf2 == c["nf2"], "dummy nf mismatch"
    out_cm1 = tagged(TAG_LEAF, c["out_inner1"], c["out_value1"])
    out_cm2 = tagged(TAG_LEAF, c["out_inner2"], c["out_value2"])
    assert out_cm1 == c["out_cm1"] and out_cm2 == c["out_cm2"], "out_cm mismatch"

    t = vecs["tree"]
    zeros = [0]
    for _ in range(int(t["depth"])):
        zeros.append(p2(zeros[-1], zeros[-1]))
    assert zeros[-1] == int(t["root_empty"]), "empty root mismatch"

    n = len(vecs["poseidon2"]) + len(vecs["poseidon3"])
    print(f"poseidon_bn254.py matches circomlibjs: {n} vectors + pool chain + empty root")


if __name__ == "__main__":
    _check()
