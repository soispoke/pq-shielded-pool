# Security

## Status

This repository is unaudited research software. Do not deploy it with real
value. The committed Groth16 verifier uses a testbed trusted setup whose toxic
waste is not independently controlled.

## Security model

The asset model is native ETH only. Deposits enter as `msg.value`; all note
values, public amounts, fees, withdrawals, and payer credits are denominated
in wei and settle as ETH. No ERC-20 contract is called, and the optional
paymaster neither accepts tokens nor converts a token-denominated fee into ETH.

The pool is frame-native and depends on the Hegotá implementations of
EIP-8141, EIP-8250, and EIP-8272. Its two nullifiers are consumed by protocol
state at payment approval. The core transaction has two frames: the pool's
VERIFY frame authenticates the proof and keyed nonces, then approves execution
and payment together; the pool's SENDER frame settles. The pool is both sender
and payer. A separate paymaster is not required. An optional sponsored form
inserts a payment-only VERIFY frame. Settlement accepts only these two exact
grammars and the envelope values returned by `EnvelopeProbe.yul`.

The pool deliberately keeps no second spent set. A settlement revert after
approval permanently consumes the notes. Pull credits remove recipient-call
failures, and fee routing has no calldata choice: settlement credits the
nonzero, right-aligned payer authenticated by `TXPARAM(0x11)`. Tests cover
malformed payer words, self-paying settlement, external payer credits, and the
envelope and proof failure paths. Tree
exhaustion remains an explicit testbed limit: retire the pool before its
depth-20 tree reaches capacity.

The preferred deployment is an immutable Yul dispatcher at the pool address
with a Solidity settlement implementation behind `DELEGATECALL`. Proof
verification happens once, inline in the dispatcher's frame-0 authorization.
That optimization relies on the dispatcher bytecode and its verifier address
being immutable. Both addresses are embedded in the deployed code tail rather
than stored in mutable storage. The implementation remains unaudited, and the
dispatcher-to-implementation storage layout is therefore a security boundary;
the Forge suite pins it explicitly.

Proofs are domain-separated by chain ID and the pool's EIP-8272 source ID.
The circuit rejects equal nullifiers and range-checks all values to 128 bits.

## Dependencies

The onchain contracts have no package-manager dependencies. JavaScript
packages are used only to compile circuits, generate test proofs, and export
vectors. `npm audit` currently reports high-severity transitive advisories in
the pinned circom/snarkjs toolchain. Do not expose these tools as a network
service or run them on untrusted inputs. CI rejects critical advisories and
checks generated artifacts against independent Solidity and Python vectors.

## Reporting

Report vulnerabilities privately to the repository owner before opening a
public issue. Include the affected commit, a minimal reproduction, impact, and
any proposed mitigation. Do not test against public deployments or third-party
infrastructure without permission.
