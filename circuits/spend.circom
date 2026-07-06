pragma circom 2.0.8;

// Shielded-pool JOIN-SPLIT spend circuit, BN254 edition (Groth16 / circom).
//
// Arbitrary-value notes: a spend consumes up to two input notes and creates
// two output notes, with a public withdrawal amount and a public fee. It is
// built to exercise two envelope features end to end:
//
//   - EIP-8250 MULTI-KEY nonces: the two nullifiers are consumed as ONE
//     keyed-nonce set (shared nonce_seq = 0, atomic, per-sender domain), the
//     `nonce_keys` list shape bounded by MAX_NONCE_KEYS = 16;
//   - the fee binding that makes a TRUSTLESS PAYMASTER possible: `fee` is a
//     public signal the proof binds, so whoever submits the spend is
//     reimbursed from shielded value by the contract itself, and no relayer
//     needs trusting.
//
// What it proves (hiding keys, secrets, values, and both Merkle paths):
//
//     I own the input notes committed in the pool's tree at the anchored
//     root (or they are zero-value dummies), their value equals the output
//     notes' value plus the public amount plus the fee, every value is a
//     128-bit integer, and I expose exactly the two nullifiers, two output
//     commitments, public amount, fee, and context as public signals.
//
// Note structure (value-carrying):
//     owner_pk = Poseidon(TAG_PK,   spend_key, 0)
//     inner    = Poseidon2(owner_pk, rho)          # what a recipient reveals
//     cm       = Poseidon(TAG_LEAF, inner, value)  # shield hashes value in
//                                                  # ON-CHAIN from msg.value
//     nf       = Poseidon(TAG_NULL, spend_key, cm)
//
// The eight public signals, in the verifier's order (circom puts outputs
// first in declaration order, then public inputs in declaration order):
//     [nf1, nf2, out_cm1, out_cm2, root, public_amount, fee, ctx]
// The verifier binds each directly (one scalar mul per signal, ~6k gas),
// which is cheaper and leaner than the earlier design's Poseidon-compressed
// claim recomputed onchain (4 hash3, ~230k gas).
//
// Soundness, beyond the fixed-denomination edition's five properties:
//   6. Value conservation: v_in1 + v_in2 === v_out1 + v_out2 + public_amount
//      + fee, over range-checked values, so a spend can neither mint nor
//      overflow (six 128-bit range checks; the sum is < 2^131 << p).
//   7. Dummy inputs: an input's Merkle check is enforced through
//      (computed_root - root) * v_in === 0, so a nonzero-value input MUST be
//      in the tree while a zero-value input (needed to spend a single note
//      through the 2-input circuit) may be fabricated: it contributes zero
//      value, and its nullifier is derived from its own fabricated cm, so it
//      can never collide with (or burn) a real note's nullifier.
//   8. Same-note-twice is refused one layer up: spending one note as both
//      inputs yields nf1 == nf2, and the EIP-8250 key-set consumption
//      rejects a duplicate key in the set (NonceManager.consumeFreshMany).
//
// The four contract-side VERIFY bindings still apply, with the key-set
// binding generalised: the consumed nonce-key set must be exactly
// {nf1, nf2} at nonce_seq == 0, no extras. See ../devnet/REVIEW.md.

// resolved via -l tooling/node_modules (see tooling/setup.sh)
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";

// One input note: derive nf, walk the path, gate membership on value != 0.
template InputNote(DEPTH) {
    signal input root;
    signal input spend_key;
    signal input rho;
    signal input value;
    signal input siblings[DEPTH];
    signal input bits[DEPTH];
    signal output nf;

    for (var i = 0; i < DEPTH; i++) {
        bits[i] * (bits[i] - 1) === 0;
    }

    component pk = Poseidon(3);
    pk.inputs[0] <== 1;
    pk.inputs[1] <== spend_key;
    pk.inputs[2] <== 0;
    component inner = Poseidon(2);
    inner.inputs[0] <== pk.out;
    inner.inputs[1] <== rho;
    component leaf = Poseidon(3);
    leaf.inputs[0] <== 2;
    leaf.inputs[1] <== inner.out;
    leaf.inputs[2] <== value;

    component node[DEPTH];
    signal left[DEPTH];
    signal right[DEPTH];
    signal cur[DEPTH + 1];
    cur[0] <== leaf.out;
    for (var i = 0; i < DEPTH; i++) {
        left[i] <== cur[i] + bits[i] * (siblings[i] - cur[i]);
        right[i] <== siblings[i] + bits[i] * (cur[i] - siblings[i]);
        node[i] = Poseidon(2);
        node[i].inputs[0] <== left[i];
        node[i].inputs[1] <== right[i];
        cur[i + 1] <== node[i].out;
    }
    // membership, gated: a nonzero-value note must open at the anchored root
    (cur[DEPTH] - root) * value === 0;

    component null = Poseidon(3);
    null.inputs[0] <== 3;
    null.inputs[1] <== spend_key;
    null.inputs[2] <== leaf.out;
    nf <== null.out;
}

template Spend(DEPTH) {
    signal input root;
    signal input in_spend_key[2];
    signal input in_rho[2];
    signal input in_value[2];
    signal input in_siblings[2][DEPTH];
    signal input in_bits[2][DEPTH];
    signal input out_inner[2];   // recipients reveal inner, never their secrets
    signal input out_value[2];
    signal input public_amount;  // leaves the pool to the ctx recipient
    signal input fee;            // leaves the pool to the submitting sender
    signal input ctx;            // public; binding it needs no constraint here
    signal output nf1;
    signal output nf2;
    signal output out_cm1;
    signal output out_cm2;

    // inputs
    component note[2];
    for (var k = 0; k < 2; k++) {
        note[k] = InputNote(DEPTH);
        note[k].root <== root;
        note[k].spend_key <== in_spend_key[k];
        note[k].rho <== in_rho[k];
        note[k].value <== in_value[k];
        for (var i = 0; i < DEPTH; i++) {
            note[k].siblings[i] <== in_siblings[k][i];
            note[k].bits[i] <== in_bits[k][i];
        }
    }

    // outputs (cm = Poseidon(TAG_LEAF, inner, value), as shield computes it)
    component outCm[2];
    for (var k = 0; k < 2; k++) {
        outCm[k] = Poseidon(3);
        outCm[k].inputs[0] <== 2;
        outCm[k].inputs[1] <== out_inner[k];
        outCm[k].inputs[2] <== out_value[k];
    }

    // 6. every value is a 128-bit integer, and value is conserved
    component rc[6];
    var vals[6] = [in_value[0], in_value[1], out_value[0], out_value[1], public_amount, fee];
    for (var k = 0; k < 6; k++) {
        rc[k] = Num2Bits(128);
        rc[k].in <== vals[k];
    }
    in_value[0] + in_value[1] === out_value[0] + out_value[1] + public_amount + fee;

    nf1 <== note[0].nf;
    nf2 <== note[1].nf;
    out_cm1 <== outCm[0].out;
    out_cm2 <== outCm[1].out;
}

component main {public [root, public_amount, fee, ctx]} = Spend(20);
