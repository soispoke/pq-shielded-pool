// Regenerate ../vectors/poseidon_bn254_vectors.json and
// ../reference/poseidon_bn254_constants.json from circomlibjs itself.
//
//   node export_vectors.js
//
// circomlibjs is the same package the circuit's poseidon.circom pairs with,
// so these vectors close the loop circuit <-> reference <-> Solidity from a
// single constants source. Every vector is computed
// with BOTH the reference and the wasm implementation and asserted equal, so
// a constants mismatch inside circomlibjs itself would fail here, not later.
//
// Vector set: zero, unit, counter, and LCG-seeded
// states for Poseidon(2) and Poseidon(3), plus the pool chain from seed 2026
// (owner_pk, cm, nf, claim) and the depth-20 incremental-tree fixtures.

const fs = require("fs");
const path = require("path");
const { buildPoseidonReference, buildPoseidon } = require("circomlibjs");
const constants = JSON.parse(fs.readFileSync(
  path.join(require.resolve("circomlibjs"), "..", "..", "src", "poseidon_constants.json")));

const DEPTH = 20;

// A deterministic LCG; field elements are built from four 48-bit draws so
// the vectors are reproducible without a rand dependency.
class Lcg {
  constructor(seed) { this.s = BigInt(seed); }
  next48() {
    this.s = (this.s * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
    return (this.s >> 16n) & 0xffffffffffffn;
  }
  nextFe(p) {
    return ((this.next48() << 144n) | (this.next48() << 96n) |
            (this.next48() << 48n) | this.next48()) % p;
  }
}

async function main() {
  const ref = await buildPoseidonReference();
  const wasm = await buildPoseidon();
  const F = ref.F;
  const p = F.p;
  const s = (x) => F.toString(x); // decimal string

  function hash(inputs) {
    const a = ref(inputs.map((x) => F.e(x)));
    const b = wasm(inputs.map((x) => F.e(x)));
    if (s(a) !== s(b)) throw new Error("reference and default poseidon disagree");
    return BigInt(s(a));
  }
  const p2 = (a, b) => hash([a, b]);
  const p3 = (a, b, c) => hash([a, b, c]);

  // ---- permutation-input vectors: zero, unit, counter, 13 LCG-seeded ----
  function cases(n) {
    const out = [Array(n).fill(0n)];
    const unit = Array(n).fill(0n); unit[0] = 1n;
    out.push(unit);
    out.push(Array.from({ length: n }, (_, i) => BigInt(i + 1)));
    const lcg = new Lcg(42);
    for (let k = 0; k < 13; k++) out.push(Array.from({ length: n }, () => lcg.nextFe(p)));
    return out;
  }
  const vec2 = cases(2).map((c) => ({ in: c.map(String), out: hash(c).toString() }));
  const vec3 = cases(3).map((c) => ({ in: c.map(String), out: hash(c).toString() }));

  // ---- the pool's tagged chain (mirrors circuits/spend.circom), seed 2026 ----
  // note chain: value-carrying note, then the join-split claim over
  // (root, nf1, nf2, out_cm1, out_cm2, public_amount, fee, ctx)
  const lcg = new Lcg(2026);
  const [spend_key, rho, root, out_inner1, out_inner2, ctx_r] =
    Array.from({ length: 6 }, () => lcg.nextFe(p));
  const mask128 = (1n << 128n) - 1n;
  const value = lcg.nextFe(p) & mask128;
  const out_value1 = lcg.nextFe(p) & mask128;
  const out_value2 = lcg.nextFe(p) & mask128;
  const public_amount = lcg.nextFe(p) & mask128;
  const fee = lcg.nextFe(p) & mask128;
  const owner_pk = p3(1n, spend_key, 0n);
  const inner = p2(owner_pk, rho);
  const cm = p3(2n, inner, value);
  const nf = p3(3n, spend_key, cm);
  const nf2 = p3(3n, spend_key, p3(2n, inner, 0n)); // a dummy's nullifier
  const out_cm1 = p3(2n, out_inner1, out_value1);
  const out_cm2 = p3(2n, out_inner2, out_value2);
  const claim = p3(4n, p3(root, nf, nf2),
                   p3(out_cm1, out_cm2, p3(public_amount, fee, ctx_r)));

  // ---- depth-20 incremental-tree fixtures (mirrors ShieldedPool._append) ----
  const zeros = [0n];
  for (let l = 0; l < DEPTH; l++) zeros.push(p2(zeros[l], zeros[l]));
  function incrementalRoot(leaves) {
    const filled = Array(DEPTH).fill(0n);
    let root_ = zeros[DEPTH];
    leaves.forEach((leaf, index) => {
      let node = leaf, idx = index;
      for (let l = 0; l < DEPTH; l++) {
        if ((idx & 1) === 0) { filled[l] = node; node = p2(node, zeros[l]); }
        else { node = p2(filled[l], node); }
        idx >>= 1;
      }
      root_ = node;
    });
    return root_;
  }
  const cm0 = 1n, cm1 = 2n;

  const vectors = {
    poseidon2: vec2,
    poseidon3: vec3,
    pool_chain: Object.fromEntries(Object.entries({
      spend_key, rho, value, root, out_inner1, out_inner2, out_value1, out_value2,
      public_amount, fee, ctx: ctx_r, owner_pk, inner, cm, nf, nf2,
      out_cm1, out_cm2, claim,
    }).map(([k, v]) => [k, v.toString()])),
    tree: {
      depth: DEPTH,
      cm0: cm0.toString(), cm1: cm1.toString(),
      root_empty: zeros[DEPTH].toString(),
      root_after_cm0: incrementalRoot([cm0]).toString(),
      root_after_cm0_cm1: incrementalRoot([cm0, cm1]).toString(),
    },
  };

  const here = __dirname;
  const vpath = path.join(here, "..", "vectors", "poseidon_bn254_vectors.json");
  fs.mkdirSync(path.dirname(vpath), { recursive: true });
  fs.writeFileSync(vpath, JSON.stringify(vectors, null, 1));

  // ---- constants for the Python reference and the Solidity generator ----
  // C[t-2] is (8 + N_ROUNDS_P[t-2]) * t round constants, M[t-2] is t x t,
  // new_state[i] = sum_j M[i][j] * state[j] (poseidon_reference.js).
  const toDec = (x) => BigInt(x).toString();
  const cpath = path.join(here, "..", "reference", "poseidon_bn254_constants.json");
  fs.mkdirSync(path.dirname(cpath), { recursive: true });
  fs.writeFileSync(cpath, JSON.stringify({
    prime: p.toString(),
    t3: { rounds_f: 8, rounds_p: 57, C: constants.C[1].map(toDec), M: constants.M[1].map((r) => r.map(toDec)) },
    t4: { rounds_f: 8, rounds_p: 56, C: constants.C[2].map(toDec), M: constants.M[2].map((r) => r.map(toDec)) },
  }, null, 1));

  console.log(`wrote ${vpath} (${vec2.length}+${vec3.length} vectors + pool chain + tree)`);
  console.log(`wrote ${cpath}`);
}

main().then(() => process.exit(0), (e) => { console.error(e); process.exit(1); });
