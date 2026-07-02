"""Generate the end-to-end smoke fixture with REAL leanVM proofs.

Plays the whole protocol on the wallet side and produces, for each spend, a
real STARK plus the publics the pool consumes:

  1. Alice shields note A; her wallet reconstructs the tree ([cm_A]), builds a
     transfer witness with the real auth path for leaf 0, and proves it.
  2. Bob's note B is the transfer's output; after it lands the tree is
     [cm_A, cm_B]; Bob's wallet builds a withdraw witness for leaf 1 and proves.

Each proof is verified off-chain by `verify-spend` (the real STARK check), and
the crux of milestone 4 is asserted here: the root the wallet computed for each
tree state equals the root the prover put in the claim. The resulting
`smoke_fixture.json` drives `script/Smoke.s.sol`, which runs the same flow
on-chain and consumes these real claims through the attester shim.

Run from the wallet/ directory:  python3 gen_smoke.py
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import wallet as w

HERE = Path(__file__).parent
PROVER = HERE.parent / "prover"
PROVE = PROVER / "target" / "release" / "prove-spend"
VERIFY = PROVER / "target" / "release" / "verify-spend"
WORK = HERE / "artifacts"
RECIPIENT = "0x00000000000000000000000000000000cafebabe"


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr, file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(str(c) for c in cmd)}")
    return r


def prove(witness, tag):
    wpath = WORK / f"witness_{tag}.json"
    ppath = WORK / f"publics_{tag}.json"
    proofpath = WORK / f"proof_{tag}.json"
    wpath.write_text(json.dumps(witness))
    run([PROVE, "--in", wpath, "--out", ppath, "--proof-out", proofpath])
    run([VERIFY, "--proof", proofpath, "--publics", ppath])  # the real STARK check
    return json.loads(ppath.read_text()), proofpath


def spend_entry(pub, proofpath, **extra):
    e = {k: pub[k + "_hex"] for k in ("root", "nf", "out_cm", "ctx", "claim")}
    # proof_hash binds the real proof in the attestation. sha256 (not keccak) is
    # fine: the contract treats proof_hash as opaque and never recomputes it; on
    # Sepolia the attester posts the proof and its hash for anyone to recheck.
    # The real STARK is verified off-chain by verify-spend above, not by a hash.
    e["proof_hash"] = "0x" + hashlib.sha256(proofpath.read_bytes()).hexdigest()
    e["proof_file"] = f"wallet/artifacts/{proofpath.name}"  # for off-chain re-verify
    e.update(extra)
    return e


def main():
    if not PROVE.exists():
        raise SystemExit("build the prover first: (cd ../prover && cargo build --release)")
    WORK.mkdir(exist_ok=True)
    # deterministic notes by default so the committed fixture is reproducible;
    # pass --random for fresh secrets.
    if "--random" not in sys.argv:
        w.set_seed(20260702)

    # notes
    sk_a, rho_a = w.new_note()
    sk_b, rho_b = w.new_note()
    cm_a = w.commitment(sk_a, rho_a)
    cm_b = w.commitment(sk_b, rho_b)

    # 1. Alice's transfer: tree [cm_A], leaf 0, output cm_B
    t1 = w.Tree()
    t1.append(cm_a)
    wt = w.build_witness(t1, 0, sk_a, rho_a, out_cm=cm_b)
    pub_t, proof_t = prove(wt, "transfer")
    assert pub_t["root_hex"] == w.hex32(t1.root()), "transfer root disagrees with the wallet tree"
    assert pub_t["out_cm_hex"] == w.hex32(cm_b), "transfer out_cm is not cm_B"

    # 2. Bob's withdraw: tree [cm_A, cm_B], leaf 1, to RECIPIENT
    t2 = w.Tree()
    t2.append(cm_a)
    t2.append(cm_b)
    ww = w.build_witness(t2, 1, sk_b, rho_b, recipient=RECIPIENT)
    pub_w, proof_w = prove(ww, "withdraw")
    assert pub_w["root_hex"] == w.hex32(t2.root()), "withdraw root disagrees with the wallet tree"
    assert pub_w["out_cm_hex"] == w.hex32(w.ZERO8), "withdraw must not create a note"

    fixture = {
        "cm_a": w.hex32(cm_a),
        "recipient": RECIPIENT,
        "transfer": spend_entry(pub_t, proof_t),
        "withdraw": spend_entry(pub_w, proof_w, recipient=RECIPIENT),
    }
    (HERE / "smoke_fixture.json").write_text(json.dumps(fixture, indent=1))
    print("real proofs generated and verified off-chain; wallet roots match the prover")
    print(f"  transfer nf {pub_t['nf_hex'][:18]}...  root {pub_t['root_hex'][:18]}...")
    print(f"  withdraw nf {pub_w['nf_hex'][:18]}...  root {pub_w['root_hex'][:18]}...")
    print(f"wrote {HERE / 'smoke_fixture.json'}")


if __name__ == "__main__":
    main()
