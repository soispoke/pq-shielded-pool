#!/usr/bin/env bash
# End-to-end smoke: real leanVM proofs through the whole stack.
#
#   1. build the prover
#   2. generate fresh witnesses from the reconstructed tree, prove them
#      (real STARKs), verify each off-chain, and write wallet/smoke_fixture.json
#   3. run the on-chain flow (shield -> transfer -> withdraw) in an in-process
#      EVM via forge, consuming those real claims through the attester shim
#
# Pass --anvil to run step 3 against a live anvil node instead (see below).
set -euo pipefail
cd "$(dirname "$0")"

echo "==> building prover"
( cd ../prover && cargo build --release --bin prove-spend --bin verify-spend )

echo "==> generating real proofs and fixture (${1:-deterministic})"
if [ "${1:-}" = "--random" ]; then
  python3 gen_smoke.py --random
else
  python3 gen_smoke.py
fi

echo "==> running the on-chain flow (forge, in-process EVM)"
( cd ../contracts && forge test --match-contract SmokeE2E -vv )

echo "==> smoke passed: a real leanVM proof was produced, verified off-chain,"
echo "    and accepted on-chain for shield -> transfer -> withdraw."
