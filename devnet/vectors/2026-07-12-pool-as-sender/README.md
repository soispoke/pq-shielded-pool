# Pool-as-sender: same-block inclusion of two private spends (2026-07-12)

The ACDE #240 design demonstrated end to end: the privacy pool contract is
itself the frame-transaction sender (`FrameTx { sender = PrivacyPool,
nonce_keys = [nA, nB], nonce_seq = 0 }`), and two independent spends through
that one sender mined in the SAME block on disjoint keyed-nonce lanes.

Deployment (all from genesis account #3 `0xf93Ee4Cf…`, deployer nonces 0-6):

    pool       0x59f33805FE1Eeba4Daa691f60e3548Ac85D5bFA9  (ShieldedPool.yul, research implementation)
    probe      0xc4ff844bc78b5d43e749a2c7ba1006d8bf9dc4bd
    verifier   0x40bB6DB6dB1168a7062A0eDBDB94B5E0A3050CB8
    poseidonT3 0xBdF6a21427A0f16eE23cb885Ab23EC113C26BBdD
    poseidonT4 0x7709f30ae5a40BAF05CFD2ef722Fa7B5D8d041Eb
    paymasterA 0x10fad47c8d6c45580b6bf48896602a78f0f03a26  (bound pool, pool)
    paymasterB 0x5535909f8d268ae5f277dc574d32bc2b3fbe2a19  (bound pool, pool)
    source_id  0xff9d7332235f51264f7c055545d9265c0f8c4b45caee780de082b744283ef9a6

The pool's deployed code was verified byte-exact against the initcode via
deployment simulation (`cast call --create`), after the naive 0xfe-split
check falsely flagged a mismatch: the optimizer appends the constructor's
zeroRoot constant as a data segment after the runtime subobject, so
everything-after-the-first-0xfe is not the runtime. `yul_pool.py` documents
this; the fe-split remains sound for the small probe/paymaster constructors.

Smoke (sender = the pool for both spends, `POOL_SENDER() == pool` on-chain):

    shield    0x4f604bf4… block 151509  1.0 ETH, root published
    transfer  0x1dd7a3a6… block 151513  paymaster A pays, frame-0 verify 247,312 gas
    withdraw  0xd4a6ff2d… block 151517  paymaster B pays, 0.55 ETH credited to 0x…cafebabe

Credits exact (0.55 recipient, 0.05 per paymaster, 0.35 change escrowed),
all three pull-claims paid out, pool balance ended at exactly the change
note. The nonce-race fixture rebuilt the tree from the Yul pool's
LeafAppended events and matched `currentRoot` exactly (event parity live).

Same-block run. Shields of two 0.25 ETH notes mined blocks 151537/151538
(151538 published shared root R `0x28212f1c…`). Both transfers were built
against root-slot 151538, dry-run valid at head 151545, then submitted
back-to-back through the public RPC:

    transfer A  0x5f4a7b85…  paymaster A  nf 0x0904…, 0x22f1…
    transfer C  0xda87b830…  paymaster B  nf 0x2da1…, 0x1e93…

    BOTH MINED IN BLOCK 151546: C at txIndex 0, A at txIndex 1, status 1.

Both were concurrently pending from one sender, so the public Hegotá
endpoint and its builder pipeline accept concurrent disjoint-key frame
transactions from one sender (EIP-8250 itself leaves EIP-8141's
one-pending-per-sender guidance in place; this shows one node
configuration's keyed-aware policy, not every ethrex configuration's).

Replays of both mined raws (archived here byte-exact) are rejected at
admission with `Nonce mismatch: expected 1, got 0`: each spend's nullifier
lane advanced to seq 1 at consumption while the other lane was untouched.

Files: deploy_config.json (live addresses and root-publication slots),
smoke_fixture.json, nonce_race_fixture.json (deterministic wallet seed),
transfer_a_raw.hex / transfer_c_raw.hex (the mined same-block raws).
