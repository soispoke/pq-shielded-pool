//! Prove one shielded-pool spend.
//!
//!   prove-spend --in witness.json [--out publics.json] [--proof-out proof.json]
//!   prove-spend --demo 20 [--withdraw] [--out ...] [--proof-out ...]
//!
//! Input: a SpendWitness JSON (see the README for the schema). Output: the
//! spend's publics (arrays + packed hex for the contracts) on stdout or --out,
//! and the serialized proof at --proof-out (default: proof.json). The proof is
//! self-verified before the tool reports success.

use pool_prover::*;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).map(|i| args.get(i + 1).cloned().unwrap_or_default())
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let witness: SpendWitness = if let Some(depth) = arg(&args, "--demo") {
        let depth: usize = depth.parse().expect("--demo takes a tree depth");
        let withdraw = args.iter().any(|a| a == "--withdraw") || arg(&args, "--recipient").is_some();
        let mut w = demo_witness(depth, withdraw, 42);
        if let Some(addr) = arg(&args, "--recipient") {
            let hex = addr.strip_prefix("0x").unwrap_or(&addr);
            let bytes: Vec<u8> = (0..20)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("bad address"))
                .collect();
            w.ctx = ctx_for_recipient(bytes.as_slice().try_into().unwrap());
        }
        w
    } else if let Some(path) = arg(&args, "--in") {
        serde_json::from_str(&std::fs::read_to_string(&path).expect("cannot read witness file"))
            .expect("witness JSON does not match the SpendWitness schema")
    } else {
        eprintln!("usage: prove-spend --in witness.json | --demo DEPTH [--withdraw]");
        eprintln!("       [--out publics.json] [--proof-out proof.json]");
        std::process::exit(2);
    };

    let outcome = prove_spend(&witness).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        std::process::exit(1);
    });

    // self-verify before reporting success
    let verify_ms = verify_spend(outcome.publics.depth, &outcome.publics.claim, outcome.proof.clone())
        .unwrap_or_else(|e| {
            eprintln!("error: fresh proof failed verification: {e}");
            std::process::exit(1);
        });

    let proof_path = arg(&args, "--proof-out").unwrap_or_else(|| "proof.json".into());
    std::fs::write(&proof_path, serde_json::to_string(&outcome.proof).unwrap())
        .expect("cannot write proof file");

    let mut out = serde_json::to_value(&outcome.publics).unwrap();
    out["prove_ms"] = format!("{:.1}", outcome.prove_ms).parse().unwrap();
    out["verify_ms"] = format!("{:.1}", verify_ms).parse().unwrap();
    out["proof_kib"] = format!("{:.1}", outcome.proof_kib).parse().unwrap();
    out["proof_file"] = proof_path.clone().into();
    out["leanvm_rev"] = LEANVM_REV.into();
    let json = serde_json::to_string_pretty(&out).unwrap();
    match arg(&args, "--out") {
        Some(p) => std::fs::write(&p, &json).expect("cannot write output file"),
        None => println!("{json}"),
    }
    eprintln!(
        "proved depth-{} {} in {:.1} ms, proof {:.1} KiB at {}, verified in {:.1} ms",
        outcome.publics.depth,
        if outcome.publics.out_cm == [0; 8] { "withdraw" } else { "transfer" },
        outcome.prove_ms, outcome.proof_kib, proof_path, verify_ms
    );
}
