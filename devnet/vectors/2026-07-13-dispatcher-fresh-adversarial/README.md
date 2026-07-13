# Dispatcher fresh-note adversarial validation (Hegotá, 2026-07-13)

This run closes the only confound in the 2026-07-12 dispatcher milestone. A
new pool and a new 0.2 ETH note were created so the transfer nullifiers were
unconsumed throughout every simulation.

Deployment:

    logic       0x322813Fd9A801c5507c9de605d63CEA4f2CE6c44
    pool        0xa85233c63b9ee964add6f2cffe00fd84eb32338f
    paymaster   0x4a679253410272dd5232b3ff7cf5dbb88f295319
    source_id   0x06ce36fcd0bfe0c2c27277331e081aa9af41313686bb94622d180cffe78aeda6

The shield transaction `0xa478e68f…c6f1` mined successfully in block 162088.
The exact same fresh transfer then produced:

    valid baseline       valid=True   payer=0x4a679253…   status=success
                         gas=1,501,203 (frame 0=246,404; frame 1=42,355;
                         frame 2=1,168,793)
    flipped pA[0] bit    valid=False  payer=None
                         violation="validation prefix frame reverted"
    settle gas = 5M      valid=False  payer=None
                         violation="validation prefix frame reverted"

The valid baseline was simulated again after both negative cases and remained
valid. This proves the negatives were not replay or nonce-mismatch failures:
neither simulation consumed the fresh nullifiers. The flipped proof failed in
the dispatcher's frame-0 proof authorization. The 5M settlement frame failed
the dispatcher's exact envelope/gas binding before payment approval.

`fresh_fixture.json` and `deploy_config.json` contain the exact proof and
deployment inputs. `valid_raw.hex`, `flipped_proof_raw.hex`, and
`down_gas_raw.hex` are the signed type-0x06 transactions passed to
`ethrex_simulateFrameTransaction`; none of the three transfer vectors was
broadcast.
