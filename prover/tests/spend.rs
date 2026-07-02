//! End-to-end tests: drift guards, prove/verify at depth 20 and 32 for both
//! operations with tamper rejection (the pool_circuits.patch harness, now as
//! a first-class test), and the serialize/deserialize roundtrip behind the
//! verify-spend binary. Run with --release; proving in debug is impractical.

use pool_prover::*;

/// The crate's extracted circuit must be byte-identical to the one embedded in
/// circuits/pool_circuits.patch (which spend.py's own drift guard also checks;
/// together the three copies form one loop).
#[test]
fn circuit_matches_patch() {
    let patch = include_str!("../../circuits/pool_circuits.patch");
    let added: Vec<&str> = patch
        .lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .map(|l| &l[1..])
        .collect();
    let start = added
        .iter()
        .position(|l| *l == r##"const POOL_SPEND_PROGRAM: &str = r#""##)
        .expect("patch marker not found")
        + 1;
    let end = start
        + added[start..]
            .iter()
            .position(|l| *l == r##""#;"##)
            .expect("patch end marker not found");
    let embedded = format!("\n{}\n", added[start..end].join("\n"));
    assert_eq!(embedded, spend_program(), "circuit drifted between crate and patch");
}

/// Publics derivation must match the reference model's structure: a transfer
/// demo witness yields claim == tagged(4, h8(root, nf), h8(out_cm, 0)).
#[test]
fn derive_publics_is_consistent() {
    let w = demo_witness(8, false, 7);
    let p = derive_publics(&w).unwrap();
    let root = from_u32(&p.root).unwrap();
    let nf = from_u32(&p.nf).unwrap();
    let out_cm = from_u32(&p.out_cm).unwrap();
    let ctx = from_u32(&p.ctx).unwrap();
    let claim = tagged(TAG_CLAIM, &h8(&root, &nf), &h8(&out_cm, &ctx));
    assert_eq!(to_u32(&claim), p.claim);
    assert_eq!(p.ctx, [0; 8], "transfer has zero ctx");
    assert!(p.claim_hex.starts_with("0x") && p.claim_hex.len() == 66);
}

/// The harness: prove + verify transfer and withdraw at depths 20 and 32,
/// assert a tampered claim is rejected, and print the measured numbers.
#[test]
#[cfg_attr(debug_assertions, ignore = "proving needs --release")]
fn prove_verify_and_tamper_reject() {
    let _ = prove_spend(&demo_witness(20, false, 42)).unwrap(); // warmup, as in the patch harness
    println!("\n=== pool-prover: spend proofs (WHIR rate 1/2, leanVM {}) ===", &LEANVM_REV[..7]);
    println!("{:>6}  {:>9}  {:>9}  {:>9}   op", "depth", "prove", "proof", "verify");
    for &depth in &[20usize, 32] {
        for withdraw in [false, true] {
            let w = demo_witness(depth, withdraw, 42);
            let outcome = prove_spend(&w).unwrap();
            let verify_ms =
                verify_spend(depth, &outcome.publics.claim, outcome.proof.clone()).unwrap();
            println!(
                "{:>6}  {:>7.1}ms  {:>6.1}KiB  {:>7.1}ms   {}",
                depth, outcome.prove_ms, outcome.proof_kib, verify_ms,
                if withdraw { "withdraw" } else { "transfer" }
            );
            // tampered claim must be rejected
            let mut bad = outcome.publics.claim;
            bad[0] = (bad[0] + 1) % (P as u32);
            assert!(
                verify_spend(depth, &bad, outcome.proof).is_err(),
                "tampered claim must be rejected"
            );
        }
    }
}

/// The withdraw ctx encoding must match ShieldedPool.ctxFor: the 160-bit
/// address as 8 big-endian 20-bit chunks. (Regression guard: an earlier u128
/// version wrapped the shift for the top chunks.)
#[test]
fn ctx_for_recipient_encoding() {
    let mut addr = [0u8; 20];
    addr[16..].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
    let ctx = ctx_for_recipient(&addr);
    assert_eq!(ctx, [0, 0, 0, 0, 0, 0, 0xcaf, 0xebabe]);
    // a full-width address exercises every chunk
    let addr2 = [0xffu8; 20];
    assert!(ctx_for_recipient(&addr2).iter().all(|&w| w == 0xfffff));
}

/// The verify-spend path: a proof survives JSON serialization and a fresh
/// deserialization still verifies (and still rejects a tampered claim).
#[test]
#[cfg_attr(debug_assertions, ignore = "proving needs --release")]
fn proof_serde_roundtrip() {
    let w = demo_witness(8, true, 1);
    let outcome = prove_spend(&w).unwrap();
    let json = serde_json::to_string(&outcome.proof).unwrap();
    let restored = serde_json::from_str(&json).unwrap();
    verify_spend(8, &outcome.publics.claim, restored).unwrap();
}
