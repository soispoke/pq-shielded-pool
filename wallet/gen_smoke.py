"""Generate the join-split smoke fixture with REAL Groth16 proofs.

The story, with arbitrary values and fees end to end:

  1. Alice shields 1.0 ether into note A.
  2. Alice's join-split transfer: inputs (A, dummy), outputs (Bob 0.6,
     Alice's change 0.35), fee 0.05 to the submitting sender. Two nullifiers,
     consumed on-chain as ONE EIP-8250 key set.
  3. Bob's withdraw: inputs (B, dummy), outputs (two zero-value notes),
     publicAmount 0.55 to the recipient, fee 0.05 to the sender.

Plus one adversarial proof the circuit deliberately allows and the envelope
must refuse: `attack_same_note` spends note A through BOTH inputs (valid
conservation: 1.0 + 1.0 = 2.0 of outputs). Its two nullifiers are identical,
so the EIP-8250 key-set consumption (duplicate key in one set) is the only
thing standing between it and a double-count; the test battery asserts it
reverts there.

Each honest proof is verified off-chain against the committed verification
key before it lands in the fixture. Groth16 proving is randomised, so the
fixture pairs with the committed Groth16Verifier.sol from the same setup.

Run from the wallet/ directory:  python3 gen_smoke.py [--random]
"""
import json
import subprocess
import sys
from pathlib import Path

import wallet as w
from poseidon_bn254 import p3, tagged, hex32, TAG_CLAIM

HERE = Path(__file__).parent
TOOLING = HERE.parent / "tooling"
BUILD = HERE.parent / "build"
WORK = HERE / "artifacts"
RECIPIENT = "0x00000000000000000000000000000000cafebabe"
ETH = 10**18


def run(cmd, cwd=TOOLING):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        print(r.stdout, r.stderr, file=sys.stderr)
        raise SystemExit(f"command failed: {' '.join(str(c) for c in cmd)}")
    return r


def prove(witness, tag):
    wpath = WORK / f"witness_{tag}.json"
    proofpath = WORK / f"proof_{tag}.json"
    pubpath = WORK / f"public_{tag}.json"
    wpath.write_text(json.dumps(witness))
    run(["npx", "snarkjs", "groth16", "fullprove", wpath,
         BUILD / "spend_js" / "spend.wasm", BUILD / "spend_final.zkey",
         proofpath, pubpath])
    # the real proof check, against the committed verification key
    run(["npx", "snarkjs", "groth16", "verify",
         HERE.parent / "contracts" / "vectors" / "spend_vkey.json", pubpath, proofpath])
    call = run(["npx", "snarkjs", "zkey", "export", "soliditycalldata", pubpath, proofpath])
    pa, pb, pc, _pub = json.loads("[" + call.stdout.strip() + "]")
    claim = int(json.loads(pubpath.read_text())[0])
    return claim, {"pA": pa, "pB": pb, "pC": pc}


def spend_entry(tree, inputs, outputs, public_amount, fee, ctx, claim, proof, **extra):
    root = tree.root()
    nf1, nf2 = w.input_nullifiers(inputs)
    out_cm1, out_cm2 = w.output_commitments(outputs)
    # the crux: the proof's claim binds exactly the wallet's own publics
    recomputed = tagged(TAG_CLAIM, p3(root, nf1, nf2),
                        p3(out_cm1, out_cm2, p3(public_amount, fee, ctx)))
    assert recomputed == claim, "proof claim does not bind the wallet's publics"
    e = {"root": hex32(root), "nf1": hex32(nf1), "nf2": hex32(nf2),
         "out_cm1": hex32(out_cm1), "out_cm2": hex32(out_cm2),
         "public_amount": str(public_amount), "fee": str(fee), "ctx": hex32(ctx),
         "claim": hex32(recomputed), "proof": proof}
    e.update(extra)
    return e


def main():
    zkey = BUILD / "spend_final.zkey"
    if not zkey.exists():
        raise SystemExit("run the setup first: (cd ../tooling && ./setup.sh)")
    WORK.mkdir(exist_ok=True)
    if "--random" not in sys.argv:
        w.set_seed(20260702)

    # notes: Alice's deposit, Bob's payment target, Alice's change target
    sk_a, rho_a = w.new_note()
    sk_b, rho_b = w.new_note()
    sk_a2, rho_a2 = w.new_note()
    v_shield, v_bob, v_change, v_fee = ETH, ETH * 60 // 100, ETH * 35 // 100, ETH * 5 // 100
    inner_a = w.inner(sk_a, rho_a)
    cm_a = w.commitment(sk_a, rho_a, v_shield)

    # 1+2. Alice's join-split transfer: (A, dummy) -> (Bob 0.6, change 0.35), fee 0.05
    t1 = w.Tree()
    t1.append(cm_a)
    ins_t = [{"sk": sk_a, "rho": rho_a, "value": v_shield, "idx": 0}, w.dummy_input()]
    outs_t = [(w.inner(sk_b, rho_b), v_bob), (w.inner(sk_a2, rho_a2), v_change)]
    wt = w.build_witness(t1, ins_t, outs_t, public_amount=0, fee=v_fee)
    claim_t, proof_t = prove(wt, "transfer")

    # 3. Bob's withdraw: (B, dummy) -> (0, 0), publicAmount 0.55, fee 0.05
    t2 = w.Tree()
    for cm in [cm_a, *w.output_commitments(outs_t)]:
        t2.append(cm)
    cm_b = w.commitment(sk_b, rho_b, v_bob)
    assert t2.leaves[1] == cm_b, "Bob's note is leaf 1"
    ins_w = [{"sk": sk_b, "rho": rho_b, "value": v_bob, "idx": 1}, w.dummy_input()]
    outs_w = [(w.inner(*w.new_note()), 0), (w.inner(*w.new_note()), 0)]
    v_pub = v_bob - v_fee
    ww = w.build_witness(t2, ins_w, outs_w, public_amount=v_pub, fee=v_fee,
                         recipient=RECIPIENT)
    claim_w, proof_w = prove(ww, "withdraw")

    # 4. the adversarial proof: note A through BOTH inputs (nf1 == nf2)
    ins_x = [dict(ins_t[0]), dict(ins_t[0])]
    outs_x = [(w.inner(*w.new_note()), v_shield), (w.inner(*w.new_note()), v_shield)]
    wx = w.build_witness(t1, ins_x, outs_x, public_amount=0, fee=0)
    claim_x, proof_x = prove(wx, "same_note")

    fixture = {
        "inner_a": hex32(inner_a),
        "cm_a": hex32(cm_a),
        "shield_value": str(v_shield),
        "recipient": RECIPIENT,
        "transfer": spend_entry(t1, ins_t, outs_t, 0, v_fee, 0, claim_t, proof_t,
                                # Bob's opening, so the duplicate-output no-op
                                # can be exercised on-chain (shield it first)
                                out_inner1=hex32(outs_t[0][0]),
                                out_value1=str(outs_t[0][1])),
        "withdraw": spend_entry(t2, ins_w, outs_w, v_pub, v_fee,
                                w.ctx_for_recipient(RECIPIENT), claim_w, proof_w,
                                recipient=RECIPIENT),
        "attack_same_note": spend_entry(t1, ins_x, outs_x, 0, 0, 0, claim_x, proof_x),
    }
    assert fixture["attack_same_note"]["nf1"] == fixture["attack_same_note"]["nf2"]
    (HERE / "smoke_fixture.json").write_text(json.dumps(fixture, indent=1))
    print("real join-split proofs generated and verified off-chain; claims bind the wallet roots")
    print(f"  transfer  nf1 {fixture['transfer']['nf1'][:18]}... nf2 {fixture['transfer']['nf2'][:18]}... fee {v_fee}")
    print(f"  withdraw  publicAmount {v_pub} fee {v_fee}")
    print(f"  attack_same_note proves with nf1 == nf2 (the key-set duplicate the envelope must refuse)")
    print(f"wrote {HERE / 'smoke_fixture.json'}")


if __name__ == "__main__":
    main()
