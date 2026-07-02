"""Generates ../vectors/pool_fixtures.json for the ShieldedPool tests.

Reads a withdraw publics file produced by the prover:

    cd ../../prover && cargo build --release --bin prove-spend
    ./target/release/prove-spend --demo 20 \\
        --recipient 0x00000000000000000000000000000000cafebabe \\
        --out /tmp/wd_pub.json --proof-out /tmp/wd_proof.json
    python3 gen_pool_fixtures.py            # writes ../vectors/pool_fixtures.json

The fixtures let the Solidity tests check ctxFor, computeClaim, and the
incremental Merkle tree root against values the leanVM prover / this Python
reference produced, closing the cross-language loop.
"""
import json
from pathlib import Path

from poseidon16 import compress_pair, tagged

HERE = Path(__file__).parent
PUB = Path("/tmp/wd_pub.json")
DEPTH = 20


def hexpack(words):
    return "0x" + "".join(f"{w:08x}" for w in words)


def hashpair(l, r):  # matches ShieldedPool._hashPair (packed digests)
    return compress_pair(l, r)


def main():
    p = json.loads(PUB.read_text())

    # claim composition must match the prover's own claim
    claim = tagged(4, compress_pair(p["root"], p["nf"]), compress_pair(p["out_cm"], p["ctx"]))
    assert hexpack(claim) == p["claim_hex"], "claim composition disagrees with the prover"

    # incremental Merkle tree (matches ShieldedPool._append), depth 20
    zeros = [[0] * 8]
    for _ in range(DEPTH):
        zeros.append(hashpair(zeros[-1], zeros[-1]))

    def incremental_root(leaves):
        filled = [[0] * 8] * DEPTH
        root = zeros[DEPTH]
        for index, leaf in enumerate(leaves):
            node, idx = leaf, index
            for l in range(DEPTH):
                if idx & 1 == 0:
                    filled[l] = node
                    node = hashpair(node, zeros[l])
                else:
                    node = hashpair(filled[l], node)
                idx >>= 1
            root = node
        return root

    cm0 = [1, 2, 3, 4, 5, 6, 7, 8]
    cm1 = [9, 10, 11, 12, 13, 14, 15, 16]
    fixture = {
        "ctx_cafebabe": p["ctx_hex"],
        "claim_case": {
            "root": p["root_hex"], "nf": p["nf_hex"], "out_cm": p["out_cm_hex"],
            "ctx": p["ctx_hex"], "claim": p["claim_hex"],
        },
        "tree": {
            "depth": DEPTH,
            "cm0": hexpack(cm0), "cm1": hexpack(cm1),
            "root_empty": hexpack(zeros[DEPTH]),
            "root_after_cm0": hexpack(incremental_root([cm0])),
            "root_after_cm0_cm1": hexpack(incremental_root([cm0, cm1])),
        },
    }
    out = HERE.parent / "vectors" / "pool_fixtures.json"
    out.write_text(json.dumps(fixture, indent=1))
    print(f"claim interop OK; wrote {out}")


if __name__ == "__main__":
    main()
