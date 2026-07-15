# Minimal shielded pool

A minimal, immutable native-ETH shielded pool for Ethereum. Three operations
(shield, transfer, withdraw), no ERC-20 support, no governance, no admin key.
Every note value, public amount, withdrawal, and fee is denominated in wei. A
spend is a 2-in/2-out join-split proven by a Groth16 SNARK
(circom + snarkjs) and verified onchain through the BN254 pairing precompiles,
so no offchain attester is involved.

It runs as an EIP-8141 frame-native application. The pool address is an
immutable Yul dispatcher and the frame-transaction sender. In frame 0 it binds
the envelope, verifies the proof, requires the proof-bound fee to cover maximum
transaction cost, and approves execution and payment together. Payment approval
consumes the two EIP-8250 nullifiers, then the SENDER frame calls the pool and
delegates state changes to a Solidity implementation. The pool is both sender
and payer. No paymaster is required.

An optional three-frame form inserts a payment-only VERIFY frame when an
external account should sponsor gas. That payer fronts ETH and receives its
proof-bound fee in ETH from the pool. It does not perform token conversion.
Both forms have run end to end on lambdaclass/ethrex's Hegotá devnet through
unrelated zero-balance submitters. The default two-frame path used no
paymaster: the pool paid for a private transfer and withdrawal, retained both
proof-bound fees, and paid the recipient's withdrawal claim. Its addresses,
transaction hashes, signed vectors, gas, and exact ETH accounting are in
[devnet/vectors/2026-07-15-self-paying/](devnet/vectors/2026-07-15-self-paying/).
The optional sponsored run is archived separately in
[devnet/vectors/2026-07-15-trustless-loop/](devnet/vectors/2026-07-15-trustless-loop/).

## How a spend works

A note is `cm = Poseidon(TAG_LEAF, Poseidon(owner_pk, rho), value)`; `shield`
hashes `msg.value` into the commitment onchain, so a deposit's value cannot be
misstated. A spend consumes two input notes, creates two output notes (payment
and change), and proves in-circuit:

- **membership** of each non-zero input at an anchored Merkle root (depth 20).
  A zero-value input is a dummy and contributes no value.
- **conservation** `v_in1 + v_in2 = v_out1 + v_out2 + publicAmount + fee`, with
  each value range-checked to 128 bits.
- **nine public signals**, bound directly by the verifier:
  `[nf1, nf2, outCm1, outCm2, root, domain, publicAmount, fee, ctx]` (circuit outputs
  first, then public inputs). Each costs one scalar mul onchain (~6k gas),
  far cheaper than recomputing a Poseidon-compressed digest (~230k).

Transfer sets `publicAmount = 0` and `ctx = 0`; withdraw sets `publicAmount > 0`
and `ctx` naming the recipient. Either may carry a `fee`, paid from shielded
ETH value. When the pool pays for itself, that ETH fee stays in the pool to
replenish its gas balance. In the optional sponsored form, it becomes an ETH
pull credit to the external payer authenticated by `TXPARAM(0x11)`. The settlement ABI
contains no caller-chosen fee recipient. Withdrawals are also pull credits, so
recipient code cannot revert settlement.

## Contracts

The dispatcher and settlement implementation enforce five bindings around
each proof:

1. the pool is the transaction sender and the settlement target;
2. the transaction consumed exactly `{nf1, nf2}` as its EIP-8250 keyed-nonce
   set at `nonce_seq = 0`;
3. its single protocol-validated EIP-8272 reference carries this pool's source
   ID and the proven root;
4. the transaction has either the exact two-frame self-paying shape or the
   exact three-frame sponsored shape;
5. its resolved payment payer is the pool in the self-paying shape, or the
   external payment verifier in the sponsored shape, as authenticated by
   `TXPARAM(0x11)`.

Nullifiers are separated by `domain = H(chain_id, source_id)` and the circuit
rejects `nf1 == nf2`. The duplicate-key rule repeats that check in the envelope.

```
contracts/src/
  ShieldedPoolLogic.sol Solidity settlement, incremental Merkle tree, and claims
  ShieldedPool.sol     standalone Solidity reference used as the test oracle
  Groth16Verifier.sol  snarkjs verifier (GENERATED; GPL-3.0, see NOTICE)
  PoseidonT3/T4.sol    Poseidon over BN254 (GENERATED); PoseidonBN254.sol is the facade
circuits/spend.circom  the 2-in/2-out join-split circuit
reference/             Python Poseidon reference and the Solidity generator
vectors/               Poseidon test vectors exported from circomlibjs
tooling/               npm deps, circuit compile and trusted-setup script
wallet/                witness builder, proof generation, and end-to-end scripts
devnet/
  ShieldedPoolDispatcher.yul immutable pool/sender shell and proof authorization
  ProofPaymaster.yul          optional external payment and fee binding
  EnvelopeProbe.yul           stateless envelope reader used by settlement
  dispatcher.py               reproducible dispatcher initcode generator
  pool_frametx.py             assembles, simulates, and submits frame transactions
  REVIEW.md                   live-run evidence and protocol caveats
```

## Run

```
cd tooling && npm ci && ./setup.sh   # compile the circuit, run a TESTBED trusted setup
cd ../wallet && ./smoke.sh           # generate real proofs, verify offchain, run onchain
./deploy_flow.sh                     # deploy and run the full flow on a local node
```

`devnet/pool_frametx.py transfer` and `withdraw` build the two-frame
self-paying form by default. Pass `--sponsored` to use the paymaster from the
deployment config, or `--paymaster 0x...` to select an explicit external payer.

`forge test` runs from a fresh clone: the committed proof fixtures pair with the
committed `Groth16Verifier.sol`. Re-running `setup.sh` re-randomises the
ceremony and invalidates the committed fixtures; run `wallet/gen_smoke.py` (or
`./smoke.sh`) afterward to regenerate them.

The wallet is fixture-driven, not a key store: every spend it will ever make
is pre-proven at generation time, and with `--random` the change note's key
exists only in memory and is discarded at exit. Do not shield real value with
it.

## Measured

Standard-EVM figures (via-IR, optimizer runs 5000, Poseidon as an external
library).
Depth 20, 13,509 R1CS constraints, ~600 ms to prove (snarkjs, Node), 256-byte
proofs.

| operation | gas |
|---|---:|
| verifyProofOnly | ~248k |
| shield | ~1.12M |
| transfer settlement | ~1.10M |
| withdraw settlement | ~1.14M |

Each spend inserts two output commitments into the Merkle frontier and
recomputes the 20-level root once. On the Hegotá devnet, EIP-8037's
two-dimensional gas accounting raises these figures; see
[devnet/REVIEW.md](devnet/REVIEW.md).

## Limitations

- **Native ETH only.** Deposits use `msg.value`; notes, public amounts, fees,
  withdrawals, and payer credits are wei-denominated. There is no token
  address, ERC-20 transfer path, exchange-rate oracle, or token-to-ETH
  paymaster conversion. ERC-20 pools are deliberately out of scope.
- **Trusted setup.** `tooling/setup.sh` runs a local, testbed-only ceremony
  whose toxic waste could forge membership. `PTAU=<file>` supplies a public
  powers-of-tau; a real deployment also needs a multi-party phase 2.
- **Not post-quantum.** Security rests on BN254 pairings and Groth16.
- **Amounts are public.** Shield and withdraw amounts and fees are visible
  onchain; only internal transfer amounts are hidden, and equal deposit and
  withdrawal amounts are linkable.
- **Post-approval reverts burn notes.** The protocol consumes the two
  nullifiers at payment approval, so a spend whose settle frame then reverts
  or runs out of gas leaves them spent with no outputs inserted. The tooling
  refuses to send a spend that does not simulate cleanly and never down-sizes
  its settle-frame gas; the one structural case left is a full tree.
- **Finite tree.** Depth 20 admits 1,048,576 commitments. There is no silent
  epoch rollover because old epoch roots would age out and strand notes. This
  disposable testbed must be retired before capacity.
- **Frame-native only.** Spends require the Hegotá EIP-8141/8250/8272 opcode
  surface and deliberately revert when called as ordinary EVM transactions.
- **Experimental client surface.** The dispatcher and optional max-cost
  paymaster have been exercised on one Hegotá ethrex configuration, including
  same-block disjoint-nullifier spends and replay rejection. The two-frame
  self-paying form has also completed a fresh shield, transfer, withdrawal,
  claim, and replay lifecycle. This is not evidence of compatibility with
  other clients or ethrex configurations.
- **Unaudited research code.**
