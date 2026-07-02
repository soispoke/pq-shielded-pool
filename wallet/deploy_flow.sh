#!/usr/bin/env bash
# Deploy the pool and run the real-proof flow against a live JSON-RPC node.
#
# Default (no args): spin up a local anvil, deploy, and run
# shield -> transfer -> withdraw with the real leanVM proofs from
# smoke_fixture.json, signing attestations with a standalone key via
# `cast wallet sign`. This is the faithful dress rehearsal for Sepolia.
#
# Sepolia (or any node): set the env vars below and run. Deployment is a
# real, irreversible broadcast, so it is never done implicitly.
#
#   RPC_URL         JSON-RPC endpoint (default: local anvil)
#   DEPLOYER_PK     funded key that deploys and shields
#   POOL_SENDER_PK  the pinned sender that submits spends
#   ATTESTER_PK     the attester that signs (claim, proofHash)
#   DENOM_WEI       denomination (default 1 ether)
#
# Requires: foundry (forge, cast, anvil), python3, and a built prover +
# smoke_fixture.json (run ./smoke.sh once first, or gen_smoke.py).
set -euo pipefail
cd "$(dirname "$0")"
CONTRACTS=../contracts
FIX=smoke_fixture.json
CONFIG=deploy_config.json
DOMAIN=$(cast keccak "PQ_POOL_SPEND_ATTESTATION_V1")
DENOM_WEI=${DENOM_WEI:-1000000000000000000}

[ -f "$FIX" ] || { echo "no $FIX; run ./smoke.sh first"; exit 1; }
# the standalone attester re-verifies the real proofs, so they must be present
if [ ! -f artifacts/proof_transfer.json ]; then
  echo "==> real proof artifacts missing; regenerating (needs a built prover)"
  python3 gen_smoke.py
fi

ANVIL_PID=""
cleanup() { [ -n "$ANVIL_PID" ] && kill "$ANVIL_PID" 2>/dev/null || true; }
trap cleanup EXIT

if [ -z "${RPC_URL:-}" ]; then
  echo "==> launching local anvil"
  anvil --silent --block-time 1 &
  ANVIL_PID=$!
  sleep 2
  RPC_URL=http://127.0.0.1:8545
  # standard anvil dev keys
  DEPLOYER_PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
  POOL_SENDER_PK=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
  ATTESTER_PK=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
fi

j() { python3 -c "import json,sys;print(json.load(open('$FIX'))$1)"; }
POOL_SENDER=$(cast wallet address --private-key "$POOL_SENDER_PK")
ATTESTER=$(cast wallet address --private-key "$ATTESTER_PK")
CHAINID=$(cast chain-id --rpc-url "$RPC_URL")
DEPLOYER=$(cast wallet address --private-key "$DEPLOYER_PK")
echo "==> chain $CHAINID  deployer $DEPLOYER  pool_sender $POOL_SENDER  attester $ATTESTER"

deployed() { grep -oE "Deployed to: 0x[0-9a-fA-F]{40}" | awk '{print $3}'; }
FC="forge create --root $CONTRACTS --rpc-url $RPC_URL --private-key $DEPLOYER_PK --broadcast"

echo "==> deploying"
ROOTS=$($FC src/RecentRoots.sol:RecentRoots | deployed)
VERIFIER=$($FC src/AttestedVerifier.sol:AttestedVerifier --constructor-args "$ATTESTER" | deployed)
POOL=$($FC src/ShieldedPool.sol:ShieldedPool --constructor-args "$DENOM_WEI" "$POOL_SENDER" "$ROOTS" "$VERIFIER" | deployed)
NONCES=$(cast call "$POOL" "nonces()(address)" --rpc-url "$RPC_URL")
DEPLOY_BLOCK=$(cast block-number --rpc-url "$RPC_URL")
echo "    pool $POOL  roots $ROOTS  verifier $VERIFIER  nonces $NONCES"

send() { cast send --rpc-url "$RPC_URL" "$@" >/dev/null; }
call() { cast call --rpc-url "$RPC_URL" "$@"; }

echo "==> shield cm_A"
CM_A=$(j "['cm_a']")
send --private-key "$DEPLOYER_PK" --value "$DENOM_WEI" "$POOL" "shield(bytes32)" "$CM_A"
SLOT_R1=$(call "$POOL" "lastRootSlot()(uint64)")
R1=$(call "$POOL" "currentRoot()(bytes32)")
[ "$R1" = "$(j "['transfer']['root']")" ] || { echo "R1 != fixture transfer root"; exit 1; }

echo "==> transfer (attester verifies the real proof, then signs)"
read -r T_SIG T_PH < <(ATTESTER_PK="$ATTESTER_PK" ./attest.sh "$CHAINID" "$POOL" \
  "$(j "['transfer']['publics_file']")" "$(j "['transfer']['proof_file']")")
SPEND="($R1,$SLOT_R1,$(j "['transfer']['nf']"),$(j "['transfer']['out_cm']"),$(j "['transfer']['ctx']"),$T_PH,$T_SIG)"
send --private-key "$POOL_SENDER_PK" "$POOL" \
  "transfer((bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes))" "$SPEND"
SLOT_R2=$(call "$POOL" "lastRootSlot()(uint64)")
R2=$(call "$POOL" "currentRoot()(bytes32)")
[ "$R2" = "$(j "['withdraw']['root']")" ] || { echo "R2 != fixture withdraw root"; exit 1; }

echo "==> withdraw (attester verifies the real proof, then signs)"
RECIPIENT=$(j "['recipient']")
BAL_BEFORE=$(cast balance "$RECIPIENT" --rpc-url "$RPC_URL")
read -r W_SIG W_PH < <(ATTESTER_PK="$ATTESTER_PK" ./attest.sh "$CHAINID" "$POOL" \
  "$(j "['withdraw']['publics_file']")" "$(j "['withdraw']['proof_file']")")
WSPEND="($R2,$SLOT_R2,$(j "['withdraw']['nf']"),$(j "['withdraw']['out_cm']"),$(j "['withdraw']['ctx']"),$W_PH,$W_SIG)"
send --private-key "$POOL_SENDER_PK" "$POOL" \
  "withdraw((bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes),address)" "$WSPEND" "$RECIPIENT"
BAL_AFTER=$(cast balance "$RECIPIENT" --rpc-url "$RPC_URL")
echo "    recipient balance $BAL_BEFORE -> $BAL_AFTER"
[ "$BAL_AFTER" != "$BAL_BEFORE" ] || { echo "recipient not paid"; exit 1; }

python3 - "$CHAINID" "$POOL" "$ROOTS" "$VERIFIER" "$NONCES" "$ATTESTER" "$POOL_SENDER" "$DENOM_WEI" "$DEPLOY_BLOCK" <<'PY'
import json, sys
k = ["chainId","pool","roots","verifier","nonces","attester","poolSender","denominationWei","deploymentBlock"]
json.dump(dict(zip(k, sys.argv[1:])), open("deploy_config.json","w"), indent=1)
PY
echo "==> flow complete; wrote $CONFIG"
echo "    shield + transfer + withdraw accepted with real leanVM proofs over live RPC."
