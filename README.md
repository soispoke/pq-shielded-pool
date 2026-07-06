# Minimal shielded pool

A minimal, immutable shielded pool for Ethereum. Three operations (shield,
transfer, withdraw), no token, no governance, no admin key. Notes hold an
arbitrary value; a spend is a 2-in/2-out join-split proven by a Groth16 SNARK
(circom + snarkjs) and verified onchain through the BN254 pairing precompiles,
so no offchain attester is involved.

It runs as an EIP-8141 frame-native application: a spend is one frame
transaction whose proof is verified inside the SENDER frame. The full shield →
transfer → withdraw flow has run end to end on lambdaclass/ethrex's Hegotá
devnet; addresses, transaction hashes, and gas are in
[devnet/REVIEW.md](devnet/REVIEW.md).

## How a spend works

A note is `cm = Poseidon(TAG_LEAF, Poseidon(owner_pk, rho), value)`; `shield`
hashes `msg.value` into the commitment onchain, so a deposit's value cannot be
misstated. A spend consumes two input notes, creates two output notes (payment
and change), and proves in-circuit:

- **membership** of each non-zero input at an anchored Merkle root (depth 20).
  A zero-value input is a dummy: its nullifier derives from a fabricated
  commitment and cannot collide with a real note, so a single note can be spent
  through the two-input circuit.
- **conservation** `v_in1 + v_in2 = v_out1 + v_out2 + publicAmount + fee`, with
  each value range-checked to 128 bits.
- **eight public signals**, bound directly by the verifier:
  `[nf1, nf2, outCm1, outCm2, root, publicAmount, fee, ctx]` (circuit outputs
  first, then public inputs). Each costs one scalar mul onchain (~6k gas),
  far cheaper than recomputing a Poseidon-compressed digest (~230k).

Transfer sets `publicAmount = 0` and `ctx = 0`; withdraw sets `publicAmount > 0`
and `ctx` naming the recipient. Either may carry a `fee`, paid from shielded
value to `msg.sender`.

## Contracts

The pool enforces four checks around each proof:

1. the sender is the pinned `POOL_SENDER`;
2. the 2 nullifiers are consumed as one keyed-nonce set `{nf1, nf2}`
   (EIP-8250: shared `nonce_seq = 0`, atomic all-or-nothing);
3. the proof's root is one of the pool's recent roots (EIP-8272);
4. the operation shape is well-formed (transfer vs withdraw).

Consuming the 2 nullifiers as a set makes the duplicate-key rule the defense
against spending one note through both inputs: such a spend has `nf1 == nf2`,
which the circuit accepts but the set consumption rejects, so it reverts and
spends nothing.

```
contracts/src/
  ShieldedPool.sol     the pool: Merkle tree, shield/transfer/withdraw, the four checks
  NonceManager.sol     EIP-8250 keyed nonces (consumeFreshMany, MAX_NONCE_KEYS = 16)
  RecentRoots.sol      EIP-8272 recent-roots ring
  Groth16Verifier.sol  snarkjs verifier (GENERATED; GPL-3.0, see NOTICE)
  PoseidonT3/T4.sol    Poseidon over BN254 (GENERATED); PoseidonBN254.sol is the facade
circuits/spend.circom  the 2-in/2-out join-split circuit
reference/             Python Poseidon reference and the Solidity generator
vectors/               Poseidon test vectors exported from circomlibjs
tooling/               npm deps, circuit compile and trusted-setup script
wallet/                witness builder, proof generation, and end-to-end scripts
devnet/                frame-transaction tooling and the devnet write-up (REVIEW.md)
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
Depth 20, 13,028 R1CS constraints, ~600 ms to prove (snarkjs, Node), 256-byte
proofs.

| operation | gas |
|---|---:|
| verifySpend (proof + root check) | ~243k |
| shield | ~1.20M |
| transfer | ~1.13M |
| withdraw | ~1.20M |

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
- **The duplicate-key check is soundness-critical.** Spending one note twice is
  rejected by the nullifier-set consumption, not by the circuit; a deployment
  that skipped that check would double-count. Enforcing `nf1 != nf2` in-circuit
  is a possible hardening.
- **Unaudited research code.**
