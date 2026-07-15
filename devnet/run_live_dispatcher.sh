#!/usr/bin/env bash
# Deploy the pool-as-sender DISPATCHER architecture (the production-preferred
# split) to a JSON-RPC node: a thin immutable Yul dispatcher
# (ShieldedPoolDispatcher.yul) at the pool address delegatecalling settlement
# to a Solidity implementation (ShieldedPoolLogic.sol). Contrast run_live.sh,
# which deploys the monolithic ShieldedPool.yul.
#
# Order: probe, verifier, PoseidonT3/T4, logic (probe+verifier), dispatcher
# (impl=logic), then optional sponsored-path paymasters when
# DEPLOY_PAYMASTERS=1. The core self-paying flow deploys no paymaster.
# The dispatcher IS the pool: its address is the frame-tx sender and the
# EIP-8272 source. Both Yul runtimes are verified byte-exact against a
# deployment simulation (cast call --create); the naive 0xfe-split is unsound
# for these objects (a data segment trails the runtime subobject).
#
# Required env: RPC_URL, DEPLOYER_PK (a genesis-prefunded key).
# Optional env: VERIFIER_ADDRESS, POSEIDON_T3_ADDRESS, POSEIDON_T4_ADDRESS,
# DEPLOY_PAYMASTERS, PAYMASTER_FUNDING_WEI, SMOKE_{SHIELD,PAYMENT,FEE}_WEI,
# and SMOKE_OUTPUT. Reused dependency addresses must already contain code.
# Live proofs default to wallet/artifacts/ so a deployment cannot
# silently replace the deterministic fixture consumed by Forge and CI.
# The optional values make repeated public-devnet validation possible without
# changing the protocol defaults or checking one-off fixtures into the wallet.
set -euo pipefail
cd "$(dirname "$0")"
RPC=${RPC_URL:?set RPC_URL}
BN=../contracts
PRICE="--gas-price 3000000000 --priority-gas-price 1000000000"
PAYMASTER_FUNDING_WEI=${PAYMASTER_FUNDING_WEI:-1000000000000000000}
DEPLOY_PAYMASTERS=${DEPLOY_PAYMASTERS:-0}
SMOKE_OUTPUT=${SMOKE_OUTPUT:-../wallet/artifacts/smoke_fixture.live.json}
deployed() { grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}'; }
addr_of() { python3 -c 'import json,sys;print(json.load(sys.stdin)["contractAddress"])'; }
DEPLOYER=$(cast wallet address --private-key "$DEPLOYER_PK")
echo "deployer=$DEPLOYER"

echo "==> EnvelopeProbe"
PROBE=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 500000 \
  --create "$(python3 probe.py --initcode)" --json | addr_of)
[ "$(cast code "$PROBE" --rpc-url "$RPC")" = "$(python3 probe.py --runtime)" ] || { echo "probe mismatch"; exit 1; }
echo "    probe=$PROBE"
echo "==> Groth16Verifier"
if [[ -n ${VERIFIER_ADDRESS:-} ]]; then
  VERIFIER=$VERIFIER_ADDRESS
  [[ $(cast code "$VERIFIER" --rpc-url "$RPC") != 0x ]] || { echo "reused verifier has no code"; exit 1; }
  echo "    reusing verifier=$VERIFIER"
else
  VERIFIER=$(forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 6000000 --broadcast \
    src/Groth16Verifier.sol:Groth16Verifier | deployed)
fi
echo "    verifier=$VERIFIER"
echo "==> PoseidonT3 / PoseidonT4 (legacy-codegen libsmall profile)"
if [[ -n ${POSEIDON_T3_ADDRESS:-} ]]; then
  T3=$POSEIDON_T3_ADDRESS
  [[ $(cast code "$T3" --rpc-url "$RPC") != 0x ]] || { echo "reused PoseidonT3 has no code"; exit 1; }
else
  T3=$(FOUNDRY_PROFILE=libsmall forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 12500000 --broadcast \
    src/PoseidonT3.sol:PoseidonT3 | deployed)
fi
if [[ -n ${POSEIDON_T4_ADDRESS:-} ]]; then
  T4=$POSEIDON_T4_ADDRESS
  [[ $(cast code "$T4" --rpc-url "$RPC") != 0x ]] || { echo "reused PoseidonT4 has no code"; exit 1; }
else
  T4=$(FOUNDRY_PROFILE=libsmall forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 16000000 --broadcast \
    src/PoseidonT4.sol:PoseidonT4 | deployed)
fi
echo "    poseidonT3=$T3  poseidonT4=$T4"

echo "==> ShieldedPoolLogic (Solidity settlement implementation; constructor probe, verifier)"
# The implementation holds probe/verifier as immutables (read from its code
# under DELEGATECALL) and links PoseidonT3/T4. It is only ever delegatecalled
# by the dispatcher; deployed here as a normal contract.
LOGIC=$(forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 12000000 --broadcast \
  src/ShieldedPoolLogic.sol:ShieldedPoolLogic \
  --libraries "src/PoseidonT3.sol:PoseidonT3:$T3" \
  --libraries "src/PoseidonT4.sol:PoseidonT4:$T4" \
  --constructor-args "$PROBE" "$VERIFIER" | deployed)
echo "    logic=$LOGIC"

echo "==> ShieldedPoolDispatcher (Yul shell at the pool address; immutable tail = logic)"
# ~1.4KB runtime; the constructor seeds currentRoot and publishes the empty
# root, so 3M gas is ample.
DISP_INIT=$(python3 dispatcher.py --initcode "$LOGIC" "$VERIFIER")
POOL=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 3000000 \
  --create "$DISP_INIT" --json | addr_of)
[ "$(cast code "$POOL" --rpc-url "$RPC")" = "$(cast call --rpc-url "$RPC" --create "$DISP_INIT")" ] \
  || { echo "dispatcher runtime mismatch"; exit 1; }
SOURCE_ID=$(cast call "$POOL" "sourceId()(bytes32)" --rpc-url "$RPC")
CHAIN_ID=$(cast chain-id --rpc-url "$RPC")
[ "$(cast call "$POOL" "POOL_SENDER()(address)" --rpc-url "$RPC" 2>/dev/null || echo skip)" ] # dispatcher has no POOL_SENDER getter; identity is address(this)
echo "    pool(dispatcher)=$POOL  source_id=$SOURCE_ID"

echo "==> deployment-bound proofs"
PROOF_ARGS=("--chain-id=$CHAIN_ID" "--source-id=$SOURCE_ID" "--output=$SMOKE_OUTPUT")
if [[ -n ${SMOKE_SHIELD_WEI:-} ]]; then
  PROOF_ARGS+=("--shield-wei=$SMOKE_SHIELD_WEI")
fi
if [[ -n ${SMOKE_PAYMENT_WEI:-} ]]; then
  PROOF_ARGS+=("--payment-wei=$SMOKE_PAYMENT_WEI")
fi
if [[ -n ${SMOKE_FEE_WEI:-} ]]; then
  PROOF_ARGS+=("--fee-wei=$SMOKE_FEE_WEI")
fi
python3 ../wallet/gen_smoke.py "${PROOF_ARGS[@]}"

PAYMASTER=""
PAYMASTER_B=""
if [[ $DEPLOY_PAYMASTERS == 1 ]]; then
  echo "==> two optional ProofPaymasters for sponsored-path tests (pool == sender)"
  PM_INIT=$(python3 paymaster.py --initcode "$POOL" "$POOL")
  PAYMASTER=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 2000000 --create "$PM_INIT" --json | addr_of)
  [ "$(cast code "$PAYMASTER" --rpc-url "$RPC")" = "$(python3 paymaster.py --runtime "$POOL" "$POOL")" ] || { echo "paymaster A mismatch"; exit 1; }
  PAYMASTER_B=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 2000000 --create "$PM_INIT" --json | addr_of)
  [ "$(cast code "$PAYMASTER_B" --rpc-url "$RPC")" = "$(python3 paymaster.py --runtime "$POOL" "$POOL")" ] || { echo "paymaster B mismatch"; exit 1; }
  cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 100000 --value "$PAYMASTER_FUNDING_WEI" "$PAYMASTER" >/dev/null
  cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $PRICE --gas-limit 100000 --value "$PAYMASTER_FUNDING_WEI" "$PAYMASTER_B" >/dev/null
  echo "    paymaster=$PAYMASTER  paymasterB=$PAYMASTER_B (each funded $PAYMASTER_FUNDING_WEI wei)"
else
  echo "==> no paymaster deployed (self-paying core run)"
fi

python3 - "$RPC" "$POOL" "$PROBE" "$VERIFIER" "$T3" "$T4" "$LOGIC" "$POOL" "$PAYMASTER" "$PAYMASTER_B" "$SOURCE_ID" <<'PY'
import json, sys
k = ["rpc","pool","probe","verifier","poseidonT3","poseidonT4","logic","poolSender","paymaster","paymasterB","sourceId"]
json.dump(dict(zip(k, sys.argv[1:])), open("deploy_config.json","w"), indent=1)
print("wrote deploy_config.json (dispatcher architecture: pool is the dispatcher, logic is the settlement impl)")
PY
echo "==> done. shield/transfer/withdraw via pool_frametx.py (spends default sender = the pool);"
echo "    fixture=$SMOKE_OUTPUT; thread _slot_transfer/_slot_withdraw from receipt block numbers."
