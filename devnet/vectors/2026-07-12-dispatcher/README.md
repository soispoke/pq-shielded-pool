# Dispatcher refactor: thin Yul shell + Solidity settlement, validated live (2026-07-12)

The production-preferred split of pool-as-sender. The monolithic 5116-byte
Yul pool is replaced by a 1425-byte immutable Yul dispatcher
(ShieldedPoolDispatcher.yul) at the pool address that DELEGATECALLs settlement
to a Solidity implementation (ShieldedPoolLogic.sol, 7352-byte runtime). The
dispatcher carries only the two concerns that must run at the sender address
in Yul under the validation observer: frame-0 envelope parsing/authentication
and inline proof verification. Settlement, the tree, claims, and all state
mutation are compiled, memory-safe Solidity reached through the proxy.

Deployment (deployer nonces continue the single-verification stack;
Poseidon/verifier/probe reused):

    logic       0xAfA2403B5701410257c2D8aD884F026E329800a7  (ShieldedPoolLogic, 7352 bytes)
    pool(disp)  0xe3275ba18f9561efd756f4e47877f142b639d164  (dispatcher, 1425 bytes, byte-exact)
    paymasterA  0x859dd09b9c3261da69bb3f35a9bc9393eff84295
    paymasterB  0x2e429b1aabce7b525d4f3635542cad7690bbc89f
    source_id   0x66f33867c949b873f68019632581e3159fd560f272a0ffcabfe4d9d9f8ab4252

Both Yul runtimes verified byte-exact against `cast call --create`.

## The delegatecall-in-VERIFY finding (why the dispatcher grew from 0.9KB)

The first dispatcher delegated EVERYTHING, including the frame-0 proof check:
verifyFrameApprove self-staticcalled verifyProofOnly, which the proxy
DELEGATECALLed to the logic. That deploy (`0x110f9fd7…`) accepted a valid
transfer at `ethrex_simulateFrameTransaction` (valid=True, frame-0 = 251,729
gas, status success) but the builder NEVER included it: pending 50+ blocks
while the chain advanced. ethrex's validation observer bans DELEGATECALL
inside a VERIFY frame (the delegate target's code could vary, breaking
validation determinism); the dry-run simulator does not enforce that, the
builder does, and a rejected validation tx is silently dropped, not errored
(the finding-4 pattern from REVIEW.md).

The fix: verify the proof INLINE in the dispatcher with a direct STATICCALL to
the immutable Groth16 verifier (observer-legal, as the monolith and
SharedPoolSender used live), computing domain in Yul. The dispatcher carries
the verifier as a second immutable (tail = impl || verifier). Settlement stays
delegated. Dispatcher grew 889 -> 1425 bytes; still 3.6x smaller than the
monolith.

## Live validation (inline-verify dispatcher 0xe3275ba1)

Smoke, sender = the pool throughout, proof verified once in frame-0 inline:

    shield    0x3698c1ad…  block 152950  1,083,164 gas
    transfer  0xd385cf3e…  block 152952  1,501,073 gas  (paymaster A)
    withdraw  0x509d8fe6…  block 152955  1,641,117 gas  (paymaster B)

Credits exact (0.55 recipient, 0.05 per paymaster, 1.0 ETH escrowed), tree at
nextIndex 5. Gas is ~7k above the monolith single-verification pool (transfer
1,494,000; withdraw 1,633,984): the DELEGATECALL proxy hop, ~0.45% per spend,
the price of collapsing 5KB of hand-audited Yul to 1.4KB plus audited Solidity.

Same-block inclusion reproven on the dispatcher: race shields blocks
152962/152963 (root published 152963), two disjoint-nullifier transfers
submitted back-to-back, BOTH MINED IN BLOCK 152969 (A idx 0 at 1,473,434 gas,
C idx 1 at 1,307,379), replays of both raws rejected at admission with
`Nonce mismatch: expected 1, got 0`.

## Adversarial note (honest confound)

Re-running the mined race transfers with a flipped proof bit or a 5M
down-gassed settle frame returns valid=False, payer=None, but the violation is
`Nonce mismatch` rather than a proof failure: those nullifiers were already
consumed by the same-block transfers, so the protocol's keyed-nonce check
rejects before frame-0's proof check runs. A clean live proof-rejection on a
fresh note needs live-tree reconstruction (gen_smoke builds against an empty
tree; this pool has 7 leaves), not run here. Frame-0's proof-rejection logic
(verifyFrame2Proof, identical public-signal set to verifyProofOnly) is covered
by contracts/test/DispatcherPool.t.sol::test_corrupted_proof_rejected_at_authentication
and is the same inline-staticcall mechanism the monolith proved live.

Files: deploy_config.json, dispatcher_smoke_fixture.json (live smoke, chain
3151908), nonce_race_fixture.json, transfer_a_raw.hex / transfer_c_raw.hex
(the mined same-block raws).
