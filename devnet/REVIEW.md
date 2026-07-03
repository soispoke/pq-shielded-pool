# Hegotá devnet: review + shielded-pool integration

A review of lambdaclass/ethrex's `hegota-devnet` (EIP-8141 frame transactions +
EIP-8250 keyed nonces + EIP-8272 recent roots, plus EIP-7906 POST_TX) and the
plan and tooling to run the BN254 shielded pool on it as a frame-native
application. Reviewed against the live network and the branch source on
2026-07-03.

## What the devnet is, verified live

- Chain id `3151908` (`0x301824`), 6s slots, three public RPCs
  (`rpc{1,2,3}.hegota.ethrex.xyz`), Dora explorer, an IP-rate-limited faucet.
  All three RPCs answer and the chain advances (observed block ~18k).
- Frame transactions are type `0x06` with the 11-field envelope
  `[chain_id, nonce_keys, nonce_seq, sender, frames, signatures,
  max_priority_fee, max_fee, max_blob_fee, blob_hashes, recent_root_references]`;
  `frame = [mode, flags, target, gas_limit, value, data]`. I re-derived their
  encoder and it matches the repo golden vector exactly (RLP and sig_hash),
  see `frametx.py` (vendored) and the check in `pool_frametx.py`.
- Predeploys confirmed by `eth_getCode`: NONCE_MANAGER at `0x…8250` carries the
  stub `0x60006000fd` (PUSH1 0; PUSH1 0; REVERT, matching the test harness),
  and RECENT_ROOT_ADDRESS at `0x…8272` has empty code (its 64-byte
  `salt‖root` write is handled natively).

## The frame execution model (from crates/vm/levm)

Four frame modes: DEFAULT (0, caller is ENTRY_POINT `0x…aa`), VERIFY (1, static
validation that grants approval), SENDER (2, executes as `tx.sender`, the only
mode that may move `value`), POST_TX (3, trailing read-only assertion). Three
new opcodes:

- `APPROVE` (0xAA): RETURN-like, sets tx-scoped approval. Pops `(offset, len,
  scope)`. The running code's address must equal the current frame's target.
  Scope `0x0` (execution) and `0x2` (both) require `frame_target == sender`;
  scope `0x1` (payment) does **not** — it only needs execution already
  approved. So a paymaster contract that is a frame's target can approve
  payment for a sender that is not itself. This is the on-chain hook the
  trustless-paymaster fee design needs.
- `TXPARAMLOAD/SIZE/COPY` (0xB0/0xB1/0xB2): read transaction parameters by
  selector. Implemented selectors: tx_type(0x00), nonce(0x01), sender(0x02),
  fees(0x03–0x06), blob count(0x07), **sig_hash(0x08)**, frame count(0x09),
  current_frame_index(0x10), and per-frame target/data/gas/mode/status
  (0x11–0x15).

## Two gaps that block a fully-faithful binding

The pool's design (see `../README.md`) needs its on-chain VERIFY
logic to bind each proof to the transaction envelope. On this devnet, two of
those bindings cannot be done in-EVM today:

1. **No TXPARAM selector for `nonce_keys`.** The spent-set binding — "the
   consumed nonce-key set is exactly the proven nullifiers" — cannot be checked
   inside a VERIFY frame, because no selector exposes the envelope's
   `nonce_keys`. So even if a spend put `[nf1, nf2]` in `nonce_keys` (making the
   protocol's NONCE_MANAGER the real spent set), the pool could not verify that
   those keys equal the nullifiers its proof commits to. The binding would be
   trusted, not proven. Adding a `nonce_keys(index)` + `nonce_key_count`
   selector pair would close this and is the single highest-value change for
   privacy-protocol integration.
2. **No exposure of `recent_root_references`, and slot is not delivered to the
   EL.** The root-source binding cannot be checked in-EVM (no opcode reads the
   refs), and the guide notes the consensus client does not yet deliver the
   slot number, so refs "cannot fully validate end-to-end." A pool must
   therefore keep reading its own root history rather than the protocol's
   EIP-8272 entries.

A third constraint is policy, not capability: the public mempool admits only
`nonce_keys == [0]`; non-zero-key transactions are "submittable directly to
block builders." A privacy spend that used the nullifiers as keyed nonces
cannot go through the public RPC and needs a builder endpoint.

None of these is a soundness bug in the devnet; they are the expected rough
edges of an early multi-EIP testnet, and they line up exactly with the
"bindings are trusted contract code, not proven in-circuit" caveat the pool
already states. They are the concrete work items to make the envelope bindings
enforceable rather than trusted.

## Live-run findings (2026-07-03), with on-chain evidence

Attempting the real run surfaced five concrete devnet facts, each demonstrated
against the live network. Finding 4 corrects a wrong conclusion reached
earlier the same day: deployment was never blocked, the deployer key was just
underfunded, and the failure surfaced in a misleading way.

**1. Funding is via prefunded genesis accounts, not (only) the faucet.** This
is a standard Kurtosis `ethereum-package` devnet: its genesis prefunds the
well-known 21-account set (mnemonic path `m/44'/60'/0'/0/n`), keys published in
`ethereum-package`'s `genesis_constants.star`. All 21 currently hold ~1e9 test
ETH (verified live); the faucet is just account #1. So a prefunded key funds
transactions directly, no faucet needed.

**2. The faucet is stuck because it underprices, not because inclusion is
broken.** The faucet's transfer (tx `0x8894…0581318`, type-2, `maxFeePerGas`
≈ 0.001 gwei) stayed pending indefinitely while the chain produced blocks. A
properly-priced transaction is included immediately: a self-verify value
transfer at 1 gwei priority mined on the first try (tx `0xbcc1…ccbd54f`,
block 18827, a type-0x06 frame receipt with the Transfer log). That probe was
sent from a faucet-funded key, which worked only because a 21k-gas transfer's
worst-case cost fit its ~0.001 ETH balance; the same key later produced
finding 4's false alarm. The fix for the faucet is to raise its gas price.

**3. `eth_estimateGas` / `eth_call` are unusable.** Any simulated execution
fails with `slot_number must be present in Amsterdam+ blocks` (the simulated
context lacks the consensus slot that real mined blocks carry). Every tx must
therefore be sent with an explicit `--gas-limit` (to skip estimation), and
state must be read from receipts/events rather than `eth_call`. The frame-tx
tooling here already does this; general dapp tooling (wallets, `forge`
scripting) will trip over it.

**4. Plain contract creation works; the "no deploy path" conclusion was a
funding artifact.** The morning's evidence chain (creation tx reverting at
816k/1M gas, tiny creations pending forever, `DeployInstalledNoCode` from the
deploy frame, no CREATE2 factory) led to "there is no public path to deploy a
standalone application contract." That was wrong, for two stacked reasons:

  - **The deployer key was faucet-funded, not prefunded.** `devkey.txt` held
    0.0009 ETH, not the ~1e9 of a genesis account. The mempool admitted a
    200k-gas creation (admission checks `gas_limit × max_fee ≤ balance` at
    3 gwei ≈ 0.0006 ETH, just under), but the payload builder skipped it on
    every block, and non-frame txs that fail to apply are popped for the round
    yet **kept pooled**, so the tx pends forever with no error surfaced
    anywhere. A 1M-gas retry failed admission outright ("Account does not have
    enough balance"), which is what finally exposed the cause. The same tiny
    creation from a genesis-prefunded key (`gc.star` account #0) mined with
    status 1 on the first try.
  - **The morning's 1M-gas revert was out-of-gas in disguise.** Under
    EIP-8037, receipt `gasUsed` includes the state dimension: measured across
    three successful deploys, creation costs ~214k base plus **~1,545 gas per
    byte of runtime code** (about 7.7x the 200/byte deposit), so RecentRoots
    (1,122 bytes) costs 1.95M, not the ~350k a Sepolia intuition predicts.
    816k of a 1M limit was simply the point where it died.

  Two real deployment constraints survive the correction: the EIP-7825 per-tx
  gas cap of 2^24 = 16,777,216 (a 25M-gas submission is rejected with
  "Transaction gas limit exceeds maximum"), which at ~1,545 gas/byte caps a
  single deploy at roughly **10.7KB of runtime**; and `eth_estimateGas` being
  unusable (finding 3), so every deploy needs an explicit gas limit. The
  19.5KB `PoseidonBN254` library exceeded the cap (OOG at 16.59M) and was
  split into `PoseidonT3`/`PoseidonT4` (7,027 and 9,291 bytes, compiled with
  the legacy-codegen `libsmall` profile because via-IR's dispatch glue adds
  ~3KB), differential-tested against the same circomlibjs vectors, and
  deployed separately. `split_poseidon.py` in `contracts/` performs and
  documents the split.

**5. The restricted-state validation rules are mempool policy, not
consensus.** The `FrameSimViolation` rules that the earlier probes hit
(`StateWriteOutsideDeploy`, `DeployInstalledNoCode`, banned opcodes,
non-sender `SLOAD`) live in `validation_observer.rs`, which describes itself
as "a local peer policy, never a consensus rule": it is active only during
mempool simulation of the validation prefix. Deploy frames are additionally
near-vacuous on this implementation (the draft EIP's `SETDELEGATE` does not
exist in ethrex's opcode set, so a fresh EOA cannot actually satisfy
"leaves the sender with code"). None of this constrains what an included
block may do, and none of it affects the pool, whose state changes all happen
in the uncapped post-approval SENDER frame.

The remaining useful asks for the devnet authors, in order: (a) fix the
faucet gas price, and make the builder's skip-reason observable (a
perpetually-pending tx with no diagnostic is what turned a funding mistake
into a day of misdiagnosis); (b) make `eth_estimateGas` work under the
simulated-slot context; (c) add TXPARAM selectors for `nonce_keys` and
`recent_root_references` (gaps 1–2 above) so the envelope bindings become
provable in-EVM; (d) document the EIP-8037 deploy cost (~1,545 gas/byte of
runtime) and the 2^24 per-tx cap, which together bound single-tx deploys at
~10.7KB of runtime, or predeploy a CREATE2 factory so larger contracts can
be chunked.

## The integration: pool as a frame-native application

Because the pool's proof is a Groth16 SNARK and a devnet SENDER frame
executes real EVM, the proof is verified **on-chain via the pairing precompiles inside the pool
call**. No attester, no missing verifier: the whole spend, proof check
included, is an ordinary application frame. That is the end-to-end story the
three EIPs were supposed to enable, and here it needs no extra trusted party.

`pool_frametx.py` builds each interaction as a type-0x06 frame tx:

```
shield:   [ VERIFY(target=sender, self-verify sig -> APPROVE),
            SENDER(target=pool, value=amount, data=shield(inner)) ]
transfer: [ VERIFY(target=POOL_SENDER, self-verify),
            SENDER(target=pool, value=0, data=transfer(Spend)) ]  # proof verified in-frame
withdraw: same, data=withdraw(Spend, recipient)
```

The VERIFY frame is the reference self-verify pattern (the sender's default EOA
code checks the envelope signature and approves execution+payment). The SENDER
frame runs the pool call as `tx.sender`; for spends the frame sender must be
the pinned `POOL_SENDER`, which is exactly the pool's pinned-sender binding.
The pool keeps its own NonceManager and RecentRoots for the two bindings the
devnet cannot yet expose (gaps 1 and 2), so the four VERIFY bindings split into
"verified in-EVM" (proof, pinned sender via the SENDER frame, operation shape)
and "kept in the pool contract" (spent set, root source) rather than being read
from the envelope.

### Validated offline before the run

- Envelope: the frame-tx encoder reproduces the repo golden vector (RLP +
  sig_hash).
- Pool calldata: `cast` encodes the nested `Spend` tuple; selector
  `0xe60330a3` and the fixture's `nf1` are present in the calldata
  (`pool_frametx.py` cross-check).

Both layers were then exercised live end to end (next section).

### `--protocol-nonces` (the EIP-8250 spent-set experiment)

`pool_frametx.py --protocol-nonces` builds the transfer/withdraw with
`nonce_keys = sorted([nf1, nf2])`, `nonce_seq = 0`: the variant where the two
nullifiers ARE the protocol keyed-nonce set, so the devnet's NONCE_MANAGER
becomes the pool's spent set and same-note/replay protection is enforced by the
protocol. It is expected to be rejected by the public RPC (mempool admits only
`[0]`) and, even accepted, is unbound in-EVM (gap 1). It is included to
document the intended faithful mapping and to test it the moment a builder
endpoint is available.

## The live run (2026-07-03)

The full flow ran end to end on the public network, deployed from genesis
account #0 with explicit gas limits (finding 3) at 1 gwei priority:

| contract | address | deploy gas |
|---|---|---|
| RecentRoots | `0x9ECB6f04D47FA2599449AaA523bF84476f7aD80f` | 1,947,298 |
| Groth16Verifier | `0x4Af231e5E624038Cd40FC4fd5b86B39d13E1429e` | 1,921,111 |
| PoseidonT3 | `0xB0275c9A863072599ea283A143414370470a369a` | ~11.1M |
| PoseidonT4 | `0xC5FC7cE1d859E6604f1e8E57BA0f4A92858850Bc` | ~14.6M |
| ShieldedPool | `0xB29dB8A6b1C596B64f7E1dD5358d59Db73648E17` | tx `0xf435b6b8…70ded7` |
| NonceManager | `0x9f938cBfADF0633ddBA0e116F0D1D0e2a90F8E97` | created by the pool |

Then the three frame transactions, each a type-0x06 with the 80k self-VERIFY
prefix and a 10M SENDER frame (EIP-8037 accounting inflates execution gas too,
so the Sepolia-sized 3M frame would not have been safe):

- **shield** 1 ETH: tx `0xd0277767…65786b`, block 19388, status 1, 1,502,420
  gas. The `LeafAppended` root equals the fixture's transfer root, so the
  split on-chain Poseidon matches circomlibjs exactly, and RecentRoots
  recorded it at slot 19388.
- **transfer** (join-split, Groth16 verified on-chain in the SENDER frame):
  tx `0xd329f3fd…52a8cc`, block 19394, status 1, 2,871,428 gas. The two
  output notes' final root equals the fixture's withdraw root, recorded at
  slot 19394.
- **withdraw**: tx `0xace5950f…3f0c5a`, block 19401, status 1, 3,065,907 gas.
  The recipient `0x…cafebabe` ends holding exactly the proven public amount,
  0.55 ETH.

The slot values ride in as `_slot_transfer` / `_slot_withdraw` in
`deploy_config.json` (the receipt block numbers, since `eth_call` cannot read
the pool's state here). `frametx.py` is the envelope encoder, `run_live.sh`
the deploy driver, `frame_deploy.py` the deploy-frame probe used for finding
5, and `deploy_config.json` in this directory holds the live addresses.

## Bottom line

The devnet implements the three EIPs cleanly and the pool ran on it end to
end as a genuine frame-native application: shield, join-split transfer, and
withdraw all mined as type-0x06 frame transactions with the Groth16 proof
verified **on-chain inside the SENDER frame, no attester**, the milestone the
whole prototype was aiming at. Two capability gaps (no `nonce_keys` /
`recent_root_references` TXPARAM exposure) keep two of the four envelope
bindings trusted contract state rather than proven envelope properties, and
the `--protocol-nonces` variant still needs a builder endpoint to test. The
operational lessons that cost the most time were self-inflicted or
diagnosable: fund from the genesis set (not the faucet), budget deploys at
~1,545 gas per runtime byte under the 2^24 per-tx cap, and treat a
perpetually-pending tx as a builder-side rejection with no error surface.
