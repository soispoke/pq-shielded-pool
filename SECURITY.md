# Security

## Status

This repository is unaudited research software. Do not deploy it with real
value. The committed Groth16 verifier uses a testbed trusted setup whose toxic
waste is not independently controlled.

## Security model

The pool is frame-native and depends on the Hegotá implementations of
EIP-8141, EIP-8250, and EIP-8272. Its two nullifiers are consumed by protocol
state at payment approval. Settlement therefore assumes the exact three-frame
grammar and the envelope values returned by `EnvelopeProbe.yul`.

The pool deliberately keeps no second spent set. A settlement revert after
approval permanently consumes the notes. Pull credits remove recipient-call
failures, the paymaster binds a nonzero fee recipient, and tests cover the
envelope and proof failure paths. Tree exhaustion remains an explicit testbed
limit: retire the pool before its depth-20 tree reaches capacity.

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
