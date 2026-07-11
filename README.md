# Minimal shielded pool

A minimal, immutable shielded pool for Ethereum. Three operations (shield,
transfer, withdraw), no token, no governance, no admin key. Notes hold an
arbitrary value; a spend is a 2-in/2-out join-split proven by a Groth16 SNARK
(circom + snarkjs) and verified onchain through the BN254 pairing precompiles,
so no offchain attester is involved.

It runs as an EIP-8141 frame-native application. The paymaster verifies the
proof before payment approval, when EIP-8250 consumes the two nullifiers; the
pool verifies it again before settlement. The full shield → transfer → withdraw
flow has run end to end on lambdaclass/ethrex's Hegotá devnet; addresses,
transaction hashes, and gas are in
[devnet/REVIEW.md](devnet/REVIEW.md).

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
value as a pull credit to the envelope-bound fee recipient. Withdrawals are
also pull credits, so recipient code cannot revert settlement.

## Contracts

The pool enforces four bindings around each proof:

1. the sender is the pinned `POOL_SENDER`;
2. the transaction consumed exactly `{nf1, nf2}` as its EIP-8250 keyed-nonce
   set at `nonce_seq = 0`;
3. its single protocol-validated EIP-8272 reference carries this pool's source
   ID and the proven root;
4. the transaction has the exact three-frame settlement shape.

Nullifiers are separated by `domain = H(chain_id, source_id)` and the circuit
rejects `nf1 == nf2`. The duplicate-key rule repeats that check in the envelope.

```
contracts/src/
  ShieldedPool.sol     the frame-native pool and incremental Merkle tree
  Groth16Verifier.sol  snarkjs verifier (GENERATED; GPL-3.0, see NOTICE)
  PoseidonT3/T4.sol    Poseidon over BN254 (GENERATED); PoseidonBN254.sol is the facade
circuits/spend.circom  the 2-in/2-out join-split circuit
reference/             Python Poseidon reference and the Solidity generator
vectors/               Poseidon test vectors exported from circomlibjs
tooling/               npm deps, circuit compile and trusted-setup script
wallet/                witness builder, proof generation, and end-to-end scripts
devnet/
  ProofPaymaster.yul   proof, key-set, root-reference, and frame binding
  EnvelopeProbe.yul   stateless envelope reader used by settlement
  REVIEW.md            live-run evidence and protocol caveats
```

## Run

```
cd tooling && npm ci && ./setup.sh   # compile the circuit, run a TESTBED trusted setup
cd ../wallet && ./smoke.sh           # generate real proofs, verify offchain, run onchain
./deploy_flow.sh                     # deploy and run the full flow on a local node
```

`forge test` runs from a fresh clone: the committed proof fixtures pair with the
committed `Groth16Verifier.sol`. Re-running `setup.sh` re-randomises the
ceremony and invalidates the committed fixtures; run `wallet/gen_smoke.py` (or
`./smoke.sh`) afterward to regenerate them.

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

- **Trusted setup.** `tooling/setup.sh` runs a local, testbed-only ceremony
  whose toxic waste could forge membership. `PTAU=<file>` supplies a public
  powers-of-tau; a real deployment also needs a multi-party phase 2.
- **Not post-quantum.** Security rests on BN254 pairings and Groth16.
- **Amounts are public.** Shield and withdraw amounts and fees are visible
  onchain; only internal transfer amounts are hidden, and equal deposit and
  withdrawal amounts are linkable.
- **Finite tree.** Depth 20 admits 1,048,576 commitments. There is no silent
  epoch rollover because old epoch roots would age out and strand notes. Once
  full, a newly approved spend with fresh outputs would revert after protocol
  nonce consumption. This disposable testbed must be retired before capacity.
- **Frame-native only.** Spends require the Hegotá EIP-8141/8250/8272 opcode
  surface and deliberately revert when called as ordinary EVM transactions.
- **Unaudited research code.**
