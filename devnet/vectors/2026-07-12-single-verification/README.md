# Single verification: settlement proof re-check removed, measured live (2026-07-12)

The settlement-frame Groth16 re-verification was removed after the focused
soundness gate passed (see REVIEW.md "Classification, and the redundant
settlement verify"): under pool-as-sender, execution approval can only come
from the pool's own immutable frame-0 code, which verifies the proof over
the byte-exact frame-2 Spend before APPROVE_EXECUTION. Settlement keeps the
cheap canonicity/range checks (validateSpend) and every envelope binding;
it drops only the second pairing call.

Deployment (deployer nonces 7-9; Poseidon/verifier/probe reused from the
2026-07-12-pool-as-sender stack):

    pool       0x09bb66c0459af4fe360ee294b380d77c69577c89  (byte-exact vs cast call --create)
    paymasterA 0xdaa35619c7e5fe7564262357690303b8b890725f  (bound pool, pool)
    paymasterB 0x6729a28cc695d8ab476095c5fc325b990c7c59dc
    source_id  0x1d60dd85f95efb8c43486f0a6d5a42eabaa6b219c4e00e668d370b8aee22edff

Measured against the double-verification pool (0x59f33805, same fixture
values, same devnet):

    transfer  0xc06e5f5e… block 152384  1,494,000 gas  (was 1,735,435: -241,435, -13.9%)
    withdraw  0x4659a79f… block 152388  1,633,984 gas  (was 1,875,441: -241,457, -12.9%)
    settle frame f2: 1,402,141 -> 1,160,688 (-241,453)

Credits exact (0.55 recipient, 0.05 per paymaster, 1.0 ETH escrowed before
race shields). Adversarial, both rejected in the validation prefix with
payer=None (the proof is enforced pre-payment by frame 0 alone now):

    flipped proof bit (race_flipped.json)  valid=False, prefix frame reverted
    down-gassed settle (--settle-gas 5M)   valid=False, prefix frame reverted

Same-block inclusion reconfirmed: race shields blocks 152397/152398 (root
published 152398), both transfers submitted back-to-back, BOTH MINED IN
BLOCK 152407 (A idx 0 at 1,465,920 gas, C idx 1 at 1,300,226), replays of
both raws rejected at admission with `Nonce mismatch: expected 1, got 0`.
