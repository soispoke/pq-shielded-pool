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
  `frame = [mode, flags, target, gas_limit, value, data]`. The encoder here,
  `frametx.py`, is vendored from the ethrex repo (see NOTICE); its
  golden-vector self-check (`python3 frametx.py`) matches the repo vector
  exactly (RLP and sig_hash).
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
  payment for a sender that is not itself. This is the onchain hook the
  trustless-paymaster fee design needs.
- `TXPARAMLOAD/SIZE/COPY` (0xB0/0xB1/0xB2): read transaction parameters by
  selector. Implemented selectors: tx_type(0x00), nonce(0x01), sender(0x02),
  fees(0x03–0x06), blob count(0x07), **sig_hash(0x08)**, frame count(0x09),
  current_frame_index(0x10), and per-frame target/data/gas/mode/status
  (0x11–0x15).

## Two gaps that block a fully-faithful binding

The pool's design (see `../README.md`) needs its onchain VERIFY
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

## Live-run findings (2026-07-03), with onchain evidence

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

**Update (2026-07-07): resolved.** `eth_call`/`eth_estimateGas` carry the slot
and work again after the 2026-07-06 update, and ethrex commit `e7e495f` adds
`ethrex_simulateFrameTransaction` (a new `ethrex_` namespace), the frame-native
dry-run those flat-call methods structurally cannot express. It runs the
mempool validation prefix and, if it passes, a read-only multi-frame execution
at head, returning validity, the prefix shape, the resolved payer, the max
cost, and total/per-frame gas, bounded by the same 2^24 per-tx cap as
`eth_estimateGas`. `pool_frametx.py` now dry-runs every spend before sending:
it aborts one the node reports invalid (surfacing the violation), prints the
resolved payer, and sizes the uncapped SENDER frame from the simulated gas
rather than over-reserving. Confirmed live against `rpc1` (v17.0.0): a shield
returns `valid`, `SelfVerify`, the self-funded payer, and a SENDER frame of
~1.275M gas, so the frame is sized to ~1.59M instead of the hardcoded 10M. The
tool degrades to the fixed limits on an endpoint that does not enable the
`ethrex_` namespace (`-32601`).

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
executes real EVM, the proof is verified **onchain via the pairing precompiles inside the pool
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

- Envelope: `python3 frametx.py` runs the encoder's golden-vector self-check
  (RLP + sig_hash).
- Pool calldata: `cast` encodes the nested `Spend` tuple; selector
  `0xe60330a3` and the fixture's `nf1` were confirmed present by inspecting
  the built calldata.

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

### Proof placement and FOCIL eligibility

Two spend shapes matter here, and they sit on opposite sides of EIP-8141's
100k mempool cap.

**Today's shape: proof in the SENDER frame.** The Groth16 verify over eight
direct public signals (~243k) cannot fit the 100k VERIFY prefix budget, so
this build checks the proof in the execution frame. That placement
is sound for this build because the spent set is contract state consumed in
the same frame: an invalid proof reverts the whole pool call and consumes
nothing. The transaction is trivially Profile 2 eligible under the FOCIL
eligibility draft (the prefix is an 80k self-verify reading only sender
state), so FOCIL can enforce inclusion of the envelope. What the envelope
cannot express in this shape is spend validity: an included-but-reverting
spend satisfies the inclusion guarantee, and a paymaster cannot condition
payment on the proof.

**The faithful shape: proof in the VERIFY prefix.** Once the nullifiers become
EIP-8250 keys consumed at payment approval, the proof must be checked before
APPROVE: key consumption survives later-frame reverts, so an execution-frame
proof check would let an invalid spend burn its nullifiers. That prefix costs
roughly 0.25M gas, over the 100k public-mempool cap but comfortably under the
FOCIL eligibility draft's `MAX_VERIFY_GAS_PER_TX = 2^20` (~1.05M). This is
exactly the draft's separation: public mempool admission and FOCIL
eligibility are different policies, and this transaction reaches includers
through a custom mempool or direct submission. The measured verification work
is ~23% of the FOCIL draft's verify budget (the earlier Poseidon-compressed
claim design measured ~62%; binding the eight publics directly in the verifier
removed all Poseidon hashing from VERIFY). The FOCIL draft charges static
declared prefix gas, not gas used, so the current 20k self-verify plus 300k pay
frame is budgeted closer to 320k plus signature cost. Tightening declared frame
gas is what converts the measured cost into more IL capacity.

**Enforcement is the index-based check.** FOCIL's stock omission rule
(end-of-block nonce and balance) cannot express keyed-nonce validity. The
mechanism that fits is the builder-claimed-index approach from the
FOCIL-native-AA thread: the builder names the block index where insertion was
attempted, attesters reconstruct state at that index (EIP-7928 BAL) and replay
the validation prefix, and "another transaction consumed this key first"
becomes a verifiable omission justification.

**The VOPS surface is the remaining constraint.** Profile 2 bounds prefix
state reads to protocol validation state plus the first `AA_VOPS_SLOT_COUNT`
storage slots of `sender` and `payer`. The pool's own NonceManager and
RecentRoots keep their state behind mappings, at keccak-derived slots outside
that surface, so moving today's contract-side checks into the prefix would not
be eligible. The faithful mapping is what fixes this: keyed nonces and
recent-root references are protocol validation state, inside the surface by
definition, read from the envelope via the TXPARAM selectors of gaps 1 and 2.
Those selectors are therefore not only what turns the trusted bindings into
proven ones; they are what makes the spend FOCIL-enforceable.

**What is done on the pool side, assuming the devnet upgrades.** The proof
check is now factored so the faithful shape is ready the moment the devnet
raises `MAX_VERIFY_GAS` and exposes the `nonce_keys` selector, and the split is
tested (contracts/test/ShieldedPool.t.sol):

- `ShieldedPool.verifySpend(Spend) view` is the whole spend validity check
  (non-zero nullifiers, EIP-8272 recent-root binding, and the Groth16 proof
  over the eight public signals, bound directly), and nothing else. It is
  `view`, so it runs under `STATICCALL`, which is what a VERIFY frame is: a
  paymaster targets it, staticcalls `verifySpend`, and `APPROVE`s payment if
  it returns. A test asserts it succeeds under a raw `staticcall` (proving no
  state writes). It deliberately omits the pinned-sender check, since a
  VERIFY frame runs as ENTRY_POINT rather than `tx.sender`; that binding stays
  in the SENDER-frame path.
- `ShieldedPool.checkKeySet(Spend, bytes32[] nonceKeys) pure` is the EIP-8250
  spent-set binding as a pure function: it asserts the transaction's
  `nonce_keys` are exactly the two proven nullifiers, distinct and sorted. The
  `ProofPaymaster` below now enforces this same rule in-VERIFY via the
  `NONCEKEYLOAD` (0xB9) opcode, turning the binding from trusted into proven.
- The `APPROVE`-emitting paymaster exists and is deployed as `ProofPaymaster`
  (`ProofPaymaster.yul`, generated by `paymaster.py`; Yul, since no compiler
  emits `APPROVE`/`NONCEKEYLOAD`). In the pay VERIFY frame it (1) binds the
  spent set, requiring `len(nonce_keys) == 2` (TXPARAM 0x0D) and
  `nonce_keys == sorted{nf1, nf2}` (NONCEKEYLOAD 0xB9); consensus enforces
  strictly-increasing keys, so the match fixes the exact set and rejects
  `nf1 == nf2` (the same-note attack); (2) STATICCALLs `verifySpend` for the
  proof/root/canonicity; (3) `APPROVE`s payment (scope 0x1, which does not
  require `frame_target == sender`) only if both hold. Structure, funding
  (`receive()` guard), and the revert paths are verified on anvil; the 0xB9
  binding executes only in a builder-included multi-key tx (see below).
  `pool_frametx.py --proof-in-verify` builds the transaction, setting
  `nonce_keys = [nf1, nf2]` so the binding has something to check.

The 2026-07-06 devnet update below has since landed the multi-VERIFY grammar
and the `NONCEKEYLOAD` / `RECENTROOTREFLOAD` accessors. What remains is split:
Ethrex-side public admission policy, verify budget, and VOPS-aware observer
rules; pool-side root-reference wiring and settle-only hardening. Once those
are in place, the SENDER frame shrinks to state changes: append the two output
commitments and pay out, with the nullifiers already consumed as protocol
keyed nonces at approval.

**Measured gas split** (standard EVM, `forge test --mt test_gas_frame_split`),
per operation, VERIFY frame (the proof check) vs exec frame (state changes):

| operation | VERIFY frame (proof) | exec frame (state) | full |
|---|---:|---:|---:|
| shield   | none (no proof)     | ~1.20M | ~1.20M |
| transfer | ~246k               | ~889k  | ~1.13M |
| withdraw | ~243k               | ~957k  | ~1.20M |

VERIFY is `verifySpend` plus `checkKeySet` (~3k): the Groth16 pairing check
plus one scalar mul per public signal (eight signals, ~6.2k each) and the
recent-root staticcall. There is no Poseidon hashing in VERIFY: the eight
publics are bound directly by the verifier rather than compressed into a
claim the contract recomputes, which cut this column from ~648k. It sits at
~23% of the FOCIL draft's `MAX_VERIFY_GAS_PER_TX = 2^20` (~1.05M) as measured
work, but FOCIL budget fill is based on declared prefix gas. With today's 20k
self-verify plus 300k pay frame limits, the static budget cost is closer to
320k plus signature cost. Both the measured proof work and the declared-prefix
budget exceed EIP-8141's 100k public-mempool cap, so a proof-in-VERIFY spend
needs a custom mempool or direct submission until admission policy changes.
The exec frame is dominated by the Merkle hashing: the two frontier inserts
share one 20-level root recompute (~21 Poseidon hash2, ~0.73M); shield is one
insert plus the same root recompute and carries no proof.
About 50k of the exec figure is today's keyed-nonce consumption, which moves to
the approval side in the faithful shape. These are vanilla-EVM numbers, and
EIP-8037 changes only the exec column: the state dimension charges writes
exclusively (`cost_per_state_byte = 1530`, so a fresh storage slot is
64 × 1530 = 97,920, a new account 120 × 1530 = 183,600, code deposit
1,530/byte; `gas_cost.rs`), while reads, hashing, precompiles, and calldata
stay regular-dimension. A static VERIFY frame cannot write state, so its
column carries over essentially unchanged. The live runs confirm this to the
gas (the deployed contract predates the batched root recompute and the
direct public signals, so its vanilla baseline is the older ~2.21M transfer):
the transfer's +658k over vanilla matches its ~6 fresh storage slots
(2 leaves, 2 root-ring entries, 2 nonce slots ≈ 588k) plus rewrites, and the
two live withdraws differ by exactly 183,600, the one-time new-account charge
for the recipient's first payout. Inlining Poseidon does NOT cut the exec
column: measured, internal linkage loses 35-80k per spend depending on
codegen, because the constant tables then pay quadratic memory expansion
inside the large exec frame instead of near-linear cost in throwaway
DELEGATECALL sub-frames (warm DELEGATECALL overhead is only ~0.2-0.6k per
call). The external-library split stays. VERIFY carries no Poseidon and sits
~60k over the Groth16 4-pairing floor (45k + 4 x 34k = 181k of precompile
cost, EIP-1108), which no Groth16 variant can beat on today's EVM.

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
  split onchain Poseidon matches circomlibjs exactly, and RecentRoots
  recorded it at slot 19388.
- **transfer** (join-split, Groth16 verified onchain in the SENDER frame):
  tx `0xd329f3fd…52a8cc`, block 19394, status 1, 2,871,428 gas. The two
  output notes' final root equals the fixture's withdraw root, recorded at
  slot 19394.
- **withdraw**: tx `0xace5950f…3f0c5a`, block 19401, status 1, 3,065,907 gas.
  The recipient `0x…cafebabe` ends holding exactly the proven public amount,
  0.55 ETH.

The slot values ride in as `_slot_transfer` / `_slot_withdraw` in
`deploy_config.json` (the receipt block numbers, since `eth_call` cannot read
the pool's state here). `frametx.py` is the envelope encoder, `run_live.sh`
the deploy driver, and `deploy_config.json` in this directory holds the live
addresses.

## The live run (2026-07-05): the optimized pool, and the faithful-shape attempt

A fresh deployment of the optimized contract (direct public signals, batched
Merkle append; the 2026-07-03 addresses run the old code) plus the first
onchain attempt at the proof-in-VERIFY shape. Same procedure: genesis-funded
deployer, explicit gas limits, 1 gwei priority. `deploy_config.json` now
records this deployment.

| contract | address |
|---|---|
| ShieldedPool | `0x303CB317624c74bB20Acbb9E13c8D745C6379826` |
| RecentRoots | `0x0EeC8BC5B2A3879A9B8997100486F4e26a4f299f` |
| Groth16Verifier | `0x34fa02cf467232c201FB9E90c786A69c7d743D8D` |
| PoseidonT3 / T4 | `0x48b90E15…12b361` / `0xF01ecC1d…5BBfb` |
| paymaster (proof-gated APPROVE) | `0xa4fd91b3…af9ab5` |

The standard flow confirms the optimization live, with every root matching
the fixture (so the new circuit, contract, and wallet agree onchain):

- **shield**: tx `0x231b3fdb…bb6cfd`, block 50172, status 1, **1,370,163**
  gas (was 1,502,420).
- **transfer**: tx `0x7f2be746…619234`, block 50269, status 1, **1,737,843**
  gas (was 2,871,428, a 39% cut; the batched append also removes most of the
  EIP-8037 fresh-slot writes).
- **withdraw**: tx `0xb2aa6899…1dbae9`, block 50274, status 1, **1,793,388**
  gas (was 3,065,907). The pool ends holding exactly the unspent change note.

**The faithful-shape attempt was admitted, never mined, evicted.** The first
`--proof-in-verify` transaction (self-verify frame + paymaster VERIFY frame +
SENDER frame) got no error and no inclusion. A bisection with a 6-byte probe
suggested the builder dropped any two-VERIFY-frame prefix. That conclusion was
wrong, and the 2026-07-06 devnet update below corrects it: the probe used the
wrong frame flags (two execution-scoped frames) and, decisively, an unfunded
paymaster. The real rule is the EIP-8141 `[only_verify, pay]` grammar with a
funded pay-frame target.

## The devnet update (2026-07-06): multi-VERIFY works; only the budget remains

The devnet advanced to ethrex v17.0.0 (commit `9d06722`) with four commits
that land on our blockers:

- **`5c16ea3`** — the mempool now admits a pay frame targeting a paymaster
  `P != sender`; the target-must-equal-sender check was correctly narrowed to
  only execution-scoped (`0x02`) VERIFY frames.
- **`9d06722`** — a trustless paymaster demo (`OpenSponsor.yul` +
  `frametx_sponsor_submit.py`) assembling the canonical
  `[only_verify(sender), pay(sponsor), sender(recipient)]` shape.
- **`587051`** — **`NONCEKEYLOAD` (0xB9)**: an opcode reading `nonce_keys[i]`
  (stack `[index] -> nonce_keys[index]`, gas 3, halt on out-of-range), and the
  commit notes it mirrors **`RECENTROOTREFLOAD`**, so the recent-root-reference
  accessor exists too. These are the two TXPARAM-style selectors the earlier
  "two capability gaps" section said were missing; both now exist.
- **`aecb138`** (branch tip, one ahead of the deployed node) — confirms
  `MAX_VERIFY_GAS = 100_000` and shrinks the demo's prefix frames to 20k + 40k.

Re-tested against this node:

- **The multi-VERIFY grammar mines.** Deploying `OpenSponsor`, funding it, and
  submitting `[only_verify(0x02, sender), pay(0x01, sponsor, verify()), SENDER]`
  mined at block 68007, status 1, with the **sponsor as payer** (it paid the
  gas; the sender paid only the transferred value). The earlier "silent drop"
  was self-inflicted: an unfunded pay-frame target reverts the prefix, and the
  pay-frame target is the payer, so it must hold ETH (OpenSponsor's
  `receive()` guard exists exactly to be fundable).
- **`eth_call` works again** (commits `70874d6`/`8dccd22` default a missing
  `slot_number` to 0), un-breaking the reads that finding 3 documented.
- **The `nonce_keys[0]`-only mempool policy is the operative wall.** Submitting
  the faithful spend (which sets `nonce_keys = [nf1, nf2]`) is rejected at
  admission: `only key-0 frame transactions are admitted to the public
  mempool`. With `nonce_keys = [0]` instead, the rejection is the budget error
  `prefix gas budget (frames + sig cost) exceeds MAX_VERIFY_GAS` (the 300k pay
  frame holding the ~243k `verifySpend` busts the 100k cap). So three
  requirements gate a faithful spend, and all three point to the same missing
  piece, a builder-direct submission path: the non-zero `nonce_keys`, the
  paymaster's observer-banned `STATICCALL`, and the verify budget.

**Pool-side, the faithful shape is built and the spent-set binding is now
proven, not trusted.** `ProofPaymaster.yul` (generated by `paymaster.py`) is
the pay-frame payer: it binds `nonce_keys == sorted{nf1, nf2}` via
`NONCEKEYLOAD` (0xB9) and `len` via TXPARAM 0x0D, STATICCALLs `verifySpend`,
and `APPROVE`s payment only if both hold. It deploys and funds on the devnet
(`receive()` guard), and its structure and revert paths are validated on anvil.
The 0xB9 read itself resolves only for `index > 0` in a builder-included
multi-key tx, so like the rest of the faithful spend it awaits a builder-direct
path. `pool_frametx.py --proof-in-verify` assembles the whole thing.

## Local end-to-end run of the faithful spend (2026-07-06, patched node)

The faithful spend ran end to end against a local ethrex built from
`hegota-devnet` (tip `aecb138`), confirming our side works once the roadmap
below lands. Because every blocker is mempool policy and none is consensus,
the only changes were to the mempool-admission path, set to their
post-roadmap values (no consensus edit): raise `FRAME_TX_MAX_VERIFY_GAS`
100k -> 2M, admit non-zero (nullifier) keyed-nonce txs, and run the prefix
simulation with an inactive observer so the paymaster's `STATICCALL` is not
banned (all three gated on `ETHREX_ADMIT_NONZERO_KEYS`). Chain id 9, Hegota at
genesis, the `0x…8250`/`0x…8272` predeploys placed in the genesis alloc.

Deployed our full stack (pool, verifier, split Poseidon, ProofPaymaster) and
ran the flow:

- **shield**: block 85, status 1, 1,370,163 gas; the `LeafAppended` root equals
  the fixture transfer root.
- **faithful transfer** (`--proof-in-verify`, `nonce_keys = [nf1, nf2]`):
  tx `0xdc24f7ce…17335e`, block 111, status 1, 2,029,698 gas. Verified:
  the transaction's **payer is the ProofPaymaster** (it paid the gas), so
  `APPROVE`-at-payment fired only because the pay frame's checks passed; the
  `NONCE_MANAGER` predeploy records `seq = 1` for both `nf1` and `nf2`, so the
  two proven nullifiers were **consumed as protocol keyed nonces**; and the
  pool root advanced to the fixture withdraw root, so the outputs settled.
- **negative control**: the same spend with `nonce_keys = [1, 2]` (not the
  proven nullifiers) is rejected, the pay frame reverts in the prefix
  simulation. The `NONCEKEYLOAD` spent-set binding is load-bearing, not
  vacuous.

So the whole faithful shape executes against the real Hegota opcodes
(`NONCEKEYLOAD` 0xB9, `APPROVE` 0xAA, native keyed-nonce consumption): proof
checked in the VERIFY prefix before approval, spent set bound to the proven
nullifiers in-EVM, nullifiers consumed as protocol state, payment approved by
the proof-gated paymaster, outputs settled in the SENDER frame. The 2.03M gas
includes a redundant second `verifySpend` in the SENDER frame (roadmap item 8).
What remains is entirely the mempool/FOCIL work below, which is ethrex-side.

## Roadmap: from consensus-valid to mempool-admitted and FOCIL-eligible

**The key fact this rests on.** The faithful spend is already valid by
consensus. Every gate that rejects it, the key-0 rule, `MAX_VERIFY_GAS`, and
the ERC-7562 observer, lives in ethrex's mempool-admission path
(`Blockchain::validate_transaction` in `crates/blockchain/blockchain.rs`, and
`LEVM::simulate_frame_validation_prefix` in `crates/vm/backends/levm/mod.rs`,
whose own docstring says "local peer policy, never consensus"). The
block-execution path (`execute_tx_in_block`) enforces none of them. So a
builder that includes the spend produces a valid block. The goal is not to
route around the mempool forever, it is to make the mempool admit these
transactions and FOCIL enforce them. Builder-direct is the interim channel to
run and test the spend while that lands.

Why this is not a config flip: a nullifier is the archetypal keyed nonce, and
a nullifier key is a different restricted-state type from an account nonce. It
is single-use, unpredictable, its sequence is always 0 -> 1, there is no
replace-by-higher-seq, and two transactions racing to consume the same key is
the normal double-spend case, not an error. The mempool and FOCIL machinery
have to treat one-time keys on their own terms.

**Ethrex-side, for public-mempool admission:**

1. **Admit one-time / non-zero keyed-nonce transactions.** Lift the key-0-only
   rule (`blockchain.rs:3057`) and add pending/replacement tracking for
   single-use keys: first-seen-wins, no seq-replacement, and graceful
   de-confliction of racing spends. This is the substantive item, and it is
   what keyed nonces were built for.
2. **Rework the verify budget.** `FRAME_TX_MAX_VERIFY_GAS = 100_000`
   (`transaction.rs:1958`, EIP-8141 mempool rule) rejects a proof-carrying
   verify (~243k measured). Raise it, or give proof-in-VERIFY spends a distinct
   budget tier.
3. **Scope the validation observer to a VOPS surface.** The observer bans the
   paymaster's external `STATICCALL`, correctly for arbitrary state reads. The
   fix is not to disable it but to define a validity-only-peeking-state surface
   the spend's validation stays inside, so it is cheaply admittable without
   arbitrary calls. Depends on the bindings reading protocol state (items 6-7).

**Ethrex-side, for FOCIL eligibility:**

4. **Map the spend into the AA VOPS profile.** Prefix reads must be protocol
   validation state: keyed nonces (done, via `NONCEKEYLOAD`) and the recent
   root (via `RECENTROOTREFLOAD`). The pool's own NonceManager/RecentRoots sit
   at keccak-derived slots outside the surface; the faithful mapping replaces
   them. See [[drafts/focil-eligibility/eip-draft]].
5. **Index-based omission check.** FOCIL's stock end-of-block rule cannot
   express keyed-nonce validity. The fit is the builder-claimed-index approach:
   the builder names the insertion index, attesters reconstruct state there
   (EIP-7928 BAL) and replay the validation prefix, so "another transaction
   consumed this key first" becomes a verifiable omission justification, which
   is exactly the nullifier-race case.

**Pool-side (our remaining work):**

6. **Wire `RECENTROOTREFLOAD`.** Bind the spend's root to a protocol
   recent-root reference in the paymaster, the way the nonce-key binding is
   done, so the root binding is proven and inside the VOPS surface. The last
   trusted binding.
7. **Harden the paymaster binding.** Check `nonce_seq == 0`, pin the calldata
   selector to `verifySpend(Spend)`, and bind the expected SENDER-frame
   settlement data before approving payment. The current redundant SENDER
   re-verification makes the local run safe, but a settle-only path needs this
   binding before that redundancy is removed.
8. **Add a settle-only SENDER entrypoint.** In the faithful shape the protocol
   consumes the keyed nonces at approval and the proof is checked in VERIFY, so
   the SENDER frame should only settle (insert outputs, pay out), not re-run
   `verifySpend` (~243k wasted) or re-consume via the pool's own NonceManager.
   Post-approval failures must be impossible or prefix-checked: tree capacity,
   payout success, duplicate-output behavior, and settlement calldata all need
   explicit handling. No collision exists today (the pool's manager is a
   separate store from the protocol NONCE_MANAGER predeploy), but the
   redundancy should go.
9. **Retire the pool's own NonceManager/RecentRoots** once the bindings read
   protocol state, for minimality.

**Submission channel (interim):** builder-direct, to run the faithful spend
before items 1-3 land. No consensus change is needed; the spend is already
valid. The devnet exposes no public builder-submission endpoint, so an
end-to-end run today means a local node acting as the builder.

Everything pool-side through item 5's dependencies is deployed and waiting: the
proof check, the paymaster, and the spent-set binding (`NONCEKEYLOAD`).

## Bottom line

The devnet implements the three EIPs cleanly and the pool ran on it end to
end as a genuine frame-native application: shield, join-split transfer, and
withdraw all mined as type-0x06 frame transactions with the Groth16 proof
verified **onchain inside the SENDER frame, no attester**, the milestone the
whole prototype was aiming at. The 2026-07-06 devnet update closed the two
capability gaps this section used to name: `NONCEKEYLOAD` (0xB9) and
`RECENTROOTREFLOAD` now expose `nonce_keys[i]` and the recent-root references
in-EVM, so both trusted bindings can become proven, and the multi-VERIFY
`[only_verify, pay]` grammar the faithful shape needs is live. What remains for
public admission is mempool policy: non-zero one-time keyed nonces, a verify
budget above the ~243k proof check, and VOPS-scoped observer rules for the
paymaster's validation call. Builder-direct is the interim path. Pool-side, the
last protocol binding is `RECENTROOTREFLOAD`, followed by paymaster hardening
and a safe settle-only SENDER entrypoint. The operational lessons that cost the
most time were self-inflicted or diagnosable: fund from the genesis set (not the
faucet), budget deploys at ~1,545 gas per runtime byte under the 2^24 per-tx
cap, fund the pay-frame paymaster (it is the payer), and treat a
perpetually-pending tx as a builder-side rejection with no error surface.
