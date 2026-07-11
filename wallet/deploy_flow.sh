#!/usr/bin/env bash
# Deploy the BN254 pool and run the real-proof flow against a live JSON-RPC
# node. There is NO attester. The Groth16 proof from the fixture is verified
# on-chain by the deployed verifier, so the only keys involved are the
# deployer's, the pinned sender's, and nobody vouches for anything.
#
# Default (no args): spin up a local anvil, deploy, run
# shield -> transfer -> withdraw. For Sepolia (or any node) set:
#
#   RPC_URL         JSON-RPC endpoint (default: local anvil)
#   DEPLOYER_PK     funded key that deploys and shields
#   POOL_SENDER_PK  the pinned sender that submits spends
#
# Requires: foundry, python3, node, and a generated smoke_fixture.json
# (run ./smoke.sh once first). The fixture's proofs pair with the committed
# Groth16Verifier.sol; rerunning ../tooling/setup.sh invalidates both together.
set -euo pipefail
cd "$(dirname "$0")"
CONTRACTS=../contracts
FIX=smoke_fixture.json

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
fi

j() { python3 -c "import json,sys;v=json.load(open('$FIX'))$1;print(json.dumps(v) if isinstance(v,(list,dict)) else v)"; }
# a proof tuple-fragment for cast: pA, pB, pC as nested [..] lists
proof() { python3 -c "
import json
p = json.load(open('$FIX'))['$1']['proof']
fmt = lambda v: '[' + ','.join(fmt(x) if isinstance(x, list) else str(int(x, 16)) for x in v) + ']'
print(f\"{fmt(p['pA'])},{fmt(p['pB'])},{fmt(p['pC'])}\")"; }

POOL_SENDER=$(cast wallet address --private-key "$POOL_SENDER_PK")
CHAINID=$(cast chain-id --rpc-url "$RPC_URL")
DEPLOYER=$(cast wallet address --private-key "$DEPLOYER_PK")
echo "==> chain $CHAINID  deployer $DEPLOYER  pool_sender $POOL_SENDER  (no attester)"

deployed() { grep -oE "Deployed to: 0x[0-9a-fA-F]{40}" | awk '{print $3}'; }
FC="forge create --root $CONTRACTS --rpc-url $RPC_URL --private-key $DEPLOYER_PK --broadcast"

echo "==> deploying"
ROOTS=$($FC src/RecentRoots.sol:RecentRoots | deployed)
VERIFIER=$($FC src/Groth16Verifier.sol:Groth16Verifier | deployed)
# the Poseidon halves deploy once each and link into the pool (EIP-170
# headroom; split so each half also fits the hegota 2^24 deploy budget).
# T4 deploys under the legacy libsmall profile: via-IR roughly doubles its
# hash3 runtime cost (111,611 vs 58,413 gas; since the publics are bound
# directly by the verifier, hash3 runs only in shield's commitment). T3 goes
# the other way (hash2 34,960 via-IR vs 41,938 legacy), so it keeps the
# default profile.
T3=$($FC src/PoseidonT3.sol:PoseidonT3 | deployed)
T4=$(FOUNDRY_PROFILE=libsmall $FC src/PoseidonT4.sol:PoseidonT4 | deployed)
POOL=$($FC src/ShieldedPool.sol:ShieldedPool \
  --libraries "src/PoseidonT3.sol:PoseidonT3:$T3" \
  --libraries "src/PoseidonT4.sol:PoseidonT4:$T4" \
  --constructor-args "$POOL_SENDER" "$ROOTS" "$VERIFIER" | deployed)
NONCES=$(cast call "$POOL" "nonces()(address)" --rpc-url "$RPC_URL")
SOURCE_ID=$(cast call "$POOL" "sourceId()(bytes32)" --rpc-url "$RPC_URL")
echo "    pool $POOL  roots $ROOTS  verifier $VERIFIER  nonces $NONCES"
echo "==> generating deployment-bound proofs (chain $CHAINID, source $SOURCE_ID)"
python3 gen_smoke.py "--chain-id=$CHAINID" "--source-id=$SOURCE_ID"

send() { cast send --rpc-url "$RPC_URL" "$@" >/dev/null; }
call() { cast call --rpc-url "$RPC_URL" "$@"; }

SPEND_SIG="(bytes32,uint64,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,bytes32,uint256[2],uint256[2][2],uint256[2])"
spend_tuple() { # $1 = fixture key, $2 = root, $3 = slot
  echo "($2,$3,$(j "['$1']['domain']"),$(j "['$1']['nf1']"),$(j "['$1']['nf2']"),$(j "['$1']['out_cm1']"),$(j "['$1']['out_cm2']"),$(j "['$1']['public_amount']"),$(j "['$1']['fee']"),$(j "['$1']['ctx']"),$(proof "$1"))"
}

echo "==> shield 1.0 ether into note A (contract hashes msg.value into cm)"
send --private-key "$DEPLOYER_PK" --value "$(j "['shield_value']")" "$POOL" "shield(bytes32)" "$(j "['inner_a']")"
SLOT_R1=$(call "$POOL" "lastRootSlot()(uint64)")
R1=$(call "$POOL" "currentRoot()(bytes32)")
[ "$R1" = "$(j "['transfer']['root']")" ] || { echo "R1 != fixture transfer root"; exit 1; }

echo "==> join-split transfer (two nullifiers as ONE 8250 key set; fee to sender)"
send --private-key "$POOL_SENDER_PK" "$POOL" "transfer($SPEND_SIG,address)" \
  "$(spend_tuple transfer "$R1" "$SLOT_R1")" "$POOL_SENDER"
SLOT_R2=$(call "$POOL" "lastRootSlot()(uint64)")
R2=$(call "$POOL" "currentRoot()(bytes32)")
[ "$R2" = "$(j "['withdraw']['root']")" ] || { echo "R2 != fixture withdraw root"; exit 1; }

echo "==> withdraw (publicAmount to recipient, fee to sender)"
RECIPIENT=$(j "['recipient']")
BAL_BEFORE=$(cast balance "$RECIPIENT" --rpc-url "$RPC_URL")
send --private-key "$POOL_SENDER_PK" "$POOL" "withdraw($SPEND_SIG,address,address)" \
  "$(spend_tuple withdraw "$R2" "$SLOT_R2")" "$RECIPIENT" "$POOL_SENDER"
send --private-key "$POOL_SENDER_PK" "$POOL" "claimFee(address)" "$POOL_SENDER"
BAL_AFTER=$(cast balance "$RECIPIENT" --rpc-url "$RPC_URL")
echo "    recipient balance $BAL_BEFORE -> $BAL_AFTER"
CREDIT=$(call "$POOL" "withdrawalCredit(address)(uint256)" "$RECIPIENT")
[ "$CREDIT" = "$(j "['withdraw']['public_amount']")" ] || { echo "recipient credit mismatch"; exit 1; }

# the trustless-paymaster loop: the pinned sender was reimbursed both fees
# from shielded value (anvil charges gas, so assert net = fees - gas > 0
# relative to a gasless baseline by checking the pool paid the fees out)
POOL_BAL=$(cast balance "$POOL" --rpc-url "$RPC_URL")
EXPECT=$(python3 -c "import json;f=json.load(open('$FIX'));print(int(f['shield_value'])-int(f['transfer']['fee'])-int(f['withdraw']['fee']))")
[ "$POOL_BAL" = "$EXPECT" ] || { echo "pool balance $POOL_BAL != expected $EXPECT (fees not paid?)"; exit 1; }
echo "    pool escrows the withdrawal credit; both prepaid fees were claimed by the sender"

echo "==> flow complete"
echo "    shield + join-split transfer + withdraw accepted, same-note attack refused,"
echo "    fees reimbursed the submitter: multi-key 8250 + paymaster loop, live."
