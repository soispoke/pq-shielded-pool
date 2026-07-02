//! Prove and verify PQ shielded pool spends.
//!
//! The circuit source is NOT duplicated here: it is extracted at compile time
//! from `circuits/spend.py` (the canonical copy, whose own drift guard ties it
//! to `circuits/pool_circuits.patch`). This crate wraps it in a library plus
//! three binaries (`prove-spend`, `verify-spend`, `export-vectors`) against
//! leanVM pinned at commit 12e6151, pulled as a git dependency.
//!
//! Digest convention: a digest is 8 KoalaBear field elements; JSON carries it
//! as 8 canonical u32s, and `pack_hex` gives the canonical 32-byte encoding
//! (8 big-endian 32-bit words) used by the contracts (devnet/README.md).

use std::collections::BTreeMap;
use std::time::Instant;

use backend::*;
use lean_compiler::*;
use lean_prover::{
    default_whir_config, prove_execution::prove_execution, prove_execution::ExecutionProof,
    verify_execution::verify_execution,
};
use lean_vm::*;
use serde::{Deserialize, Serialize};

pub const LEANVM_REV: &str = "12e61512416548e743040aab4daf83c58a5c5476";
pub const TAG_PK: u32 = 1;
pub const TAG_LEAF: u32 = 2;
pub const TAG_NULL: u32 = 3;
pub const TAG_CLAIM: u32 = 4;
pub const P: u64 = 2130706433; // KoalaBear

const SPEND_PY: &str = include_str!("../../circuits/spend.py");

/// The zkDSL circuit source, extracted from circuits/spend.py (single source
/// of truth; byte-identical to what the in-leanVM harness proves).
pub fn spend_program() -> &'static str {
    static PROG: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PROG.get_or_init(|| {
        let start = SPEND_PY
            .find("SPEND_PROGRAM = \"\"\"")
            .expect("SPEND_PROGRAM marker not found in circuits/spend.py")
            + "SPEND_PROGRAM = \"\"\"".len();
        let end = SPEND_PY[start..]
            .find("\"\"\"")
            .expect("unterminated SPEND_PROGRAM string")
            + start;
        SPEND_PY[start..end].to_string()
    })
}

/// Compile the spend circuit at a given tree depth.
pub fn compile_spend(depth: usize) -> Bytecode {
    let flags = CompilationFlags {
        replacements: BTreeMap::from([("DEPTH_PLACEHOLDER".to_string(), depth.to_string())]),
    };
    compile_program_with_flags(&ProgramSource::Raw(spend_program().to_string()), flags)
}

// ---- native-side hashing (identical to the circuit's tagged construction) ----

pub type Digest = [F; 8];

pub fn h8(l: &Digest, r: &Digest) -> Digest {
    let mut x = [F::ZERO; 16];
    x[..8].copy_from_slice(l);
    x[8..].copy_from_slice(r);
    poseidon16_compress(x)[..8].try_into().unwrap()
}

pub fn tagged(tag: u32, a: &Digest, b: &Digest) -> Digest {
    let inner = h8(a, b);
    let mut tb = [F::ZERO; 8];
    tb[0] = F::new(tag);
    h8(&tb, &inner)
}

pub fn to_u32(d: &Digest) -> [u32; 8] {
    core::array::from_fn(|i| d[i].as_canonical_u32())
}

pub fn from_u32(d: &[u32; 8]) -> Result<Digest, String> {
    for &x in d {
        if (x as u64) >= P {
            return Err(format!("{x} is not a KoalaBear field element"));
        }
    }
    Ok(core::array::from_fn(|i| F::new(d[i])))
}

/// The withdraw context digest for a recipient address: the 160-bit address
/// split into 8 big-endian 20-bit chunks, one per field element (each < 2^31).
/// Must match ShieldedPool.ctxFor in contracts/src/ShieldedPool.sol.
pub fn ctx_for_recipient(addr: &[u8; 20]) -> [u32; 8] {
    // 160 big-endian bits, then 8 chunks of 20 bits, most-significant first.
    // (Done bitwise rather than via a 160-bit integer, which does not fit u128.)
    let mut bits = [0u8; 160];
    for (i, &b) in addr.iter().enumerate() {
        for j in 0..8 {
            bits[i * 8 + j] = (b >> (7 - j)) & 1;
        }
    }
    core::array::from_fn(|c| {
        let mut v = 0u32;
        for k in 0..20 {
            v = (v << 1) | bits[c * 20 + k] as u32;
        }
        v
    })
}

/// Canonical 32-byte encoding: 8 big-endian 32-bit words, "0x"-prefixed hex.
pub fn pack_hex(d: &[u32; 8]) -> String {
    let mut s = String::with_capacity(66);
    s.push_str("0x");
    for &w in d {
        s.push_str(&format!("{w:08x}"));
    }
    s
}

// ---- wallet-facing structures ----

/// What a wallet knows when it spends: its secrets, the authentication path,
/// and the outputs. `bits[i] = 0` means the current node is the left child.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendWitness {
    pub spend_key: [u32; 8],
    pub rho: [u32; 8],
    pub siblings: Vec<[u32; 8]>,
    pub bits: Vec<u8>,
    pub out_cm: [u32; 8],
    pub ctx: [u32; 8],
}

/// The public side of a spend: what goes on-chain, in both array and packed
/// (contract) form. `claim` is the circuit's single public input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendPublics {
    pub depth: usize,
    pub root: [u32; 8],
    pub nf: [u32; 8],
    pub out_cm: [u32; 8],
    pub ctx: [u32; 8],
    pub claim: [u32; 8],
    pub root_hex: String,
    pub nf_hex: String,
    pub out_cm_hex: String,
    pub ctx_hex: String,
    pub claim_hex: String,
}

/// Recompute the publics a witness commits to (the same computation the
/// circuit performs; the contract recomputes `claim` from the on-chain rest).
pub fn derive_publics(w: &SpendWitness) -> Result<SpendPublics, String> {
    let depth = w.siblings.len();
    if w.bits.len() != depth {
        return Err("bits and siblings must have the same length".into());
    }
    if w.bits.iter().any(|&b| b > 1) {
        return Err("path bits must be 0 or 1".into());
    }
    let spend_key = from_u32(&w.spend_key)?;
    let rho = from_u32(&w.rho)?;
    let out_cm = from_u32(&w.out_cm)?;
    let ctx = from_u32(&w.ctx)?;
    let zero8 = [F::ZERO; 8];

    let owner_pk = tagged(TAG_PK, &spend_key, &zero8);
    let cm = tagged(TAG_LEAF, &owner_pk, &rho);
    let mut node = cm;
    for (bit, sib) in w.bits.iter().zip(&w.siblings) {
        let sib = from_u32(sib)?;
        node = if *bit == 0 { h8(&node, &sib) } else { h8(&sib, &node) };
    }
    let root = node;
    let nf = tagged(TAG_NULL, &spend_key, &cm);
    let claim = tagged(TAG_CLAIM, &h8(&root, &nf), &h8(&out_cm, &ctx));

    let (root, nf, out_cm, ctx, claim) =
        (to_u32(&root), to_u32(&nf), to_u32(&out_cm), to_u32(&ctx), to_u32(&claim));
    Ok(SpendPublics {
        depth,
        root_hex: pack_hex(&root),
        nf_hex: pack_hex(&nf),
        out_cm_hex: pack_hex(&out_cm),
        ctx_hex: pack_hex(&ctx),
        claim_hex: pack_hex(&claim),
        root,
        nf,
        out_cm,
        ctx,
        claim,
    })
}

fn witness_vec(w: &SpendWitness) -> Result<Vec<F>, String> {
    let mut v: Vec<F> = Vec::with_capacity(32 + 9 * w.siblings.len());
    v.extend(from_u32(&w.spend_key)?);
    v.extend(from_u32(&w.rho)?);
    for s in &w.siblings {
        v.extend(from_u32(s)?);
    }
    for &b in &w.bits {
        v.push(F::new(b as u32));
    }
    v.extend(from_u32(&w.out_cm)?);
    v.extend(from_u32(&w.ctx)?);
    Ok(v)
}

pub struct ProveOutcome {
    pub publics: SpendPublics,
    pub proof: ExecutionProof,
    pub prove_ms: f64,
    pub proof_kib: f64,
}

/// Prove a spend at WHIR rate 1/2 (the measured configuration).
pub fn prove_spend(w: &SpendWitness) -> Result<ProveOutcome, String> {
    let publics = derive_publics(w)?;
    let bc = compile_spend(publics.depth);
    let mut public_input = [F::ZERO; PUBLIC_INPUT_LEN];
    public_input.copy_from_slice(&from_u32(&publics.claim)?);
    let wv = witness_vec(w)?;
    let mut hints = Hints::default();
    hints.insert(&bc, "w", arena_vec![ArenaVec::from_slice(&wv)]);
    let witness = ExecutionWitness { hints, ..Default::default() };
    let t = Instant::now();
    let proof = prove_execution(&bc, &public_input, &witness, &default_whir_config(1), false)
        .map_err(|e| format!("proving failed: {e:?}"))?;
    let prove_ms = t.elapsed().as_secs_f64() * 1e3;
    let proof_kib = proof.proof.proof_size_fe() as f64 * 31.0 / 8.0 / 1024.0;
    Ok(ProveOutcome { publics, proof, prove_ms, proof_kib })
}

/// Verify a proof against a claim (recomputed from publics by the caller or
/// the contract). Returns the verification time in milliseconds.
pub fn verify_spend(depth: usize, claim: &[u32; 8], proof: ExecutionProof) -> Result<f64, String> {
    let bc = compile_spend(depth);
    let mut public_input = [F::ZERO; PUBLIC_INPUT_LEN];
    public_input.copy_from_slice(&from_u32(claim)?);
    let t = Instant::now();
    verify_execution(&bc, &public_input, proof.proof)
        .map_err(|e| format!("verification failed: {e:?}"))?;
    Ok(t.elapsed().as_secs_f64() * 1e3)
}

// ---- deterministic demo witnesses (for --demo, fixtures, and tests) ----

/// Simple LCG so demo witnesses need no rand dependency and are reproducible.
pub struct Lcg(pub u64);
impl Lcg {
    pub fn next_u32(&mut self) -> u32 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        ((self.0 >> 16) % P) as u32
    }
    pub fn next_digest(&mut self) -> [u32; 8] {
        core::array::from_fn(|_| self.next_u32())
    }
}

/// A seeded, self-consistent witness: random secrets and siblings, leaf index
/// 90, transfer (fresh out_cm, ctx = 0) or withdraw (out_cm = 0, random ctx).
pub fn demo_witness(depth: usize, withdraw: bool, seed: u64) -> SpendWitness {
    let mut lcg = Lcg(seed);
    let spend_key = lcg.next_digest();
    let rho = lcg.next_digest();
    let siblings: Vec<[u32; 8]> = (0..depth).map(|_| lcg.next_digest()).collect();
    let bits: Vec<u8> = (0..depth).map(|i| ((90 >> i) & 1) as u8).collect();
    let (out_cm, ctx) = if withdraw {
        ([0u32; 8], lcg.next_digest())
    } else {
        // a well-formed recipient note commitment
        let rk = from_u32(&lcg.next_digest()).unwrap();
        let rr = from_u32(&lcg.next_digest()).unwrap();
        let cm = tagged(TAG_LEAF, &tagged(TAG_PK, &rk, &[F::ZERO; 8]), &rr);
        (to_u32(&cm), [0u32; 8])
    };
    SpendWitness { spend_key, rho, siblings, bits, out_cm, ctx }
}
