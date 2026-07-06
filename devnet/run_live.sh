#!/usr/bin/env bash
# Deploy the BN254 join-split pool to a JSON-RPC node. This script deploys
# only; run the shield/transfer/withdraw flow with pool_frametx.py afterward
# (see the closing note). Deployment is plain contract-creation
# (this works on the Hegotá devnet; the earlier "no deploy path" finding was a
# funding artifact, see REVIEW.md finding 4); the spends are EIP-8141 frame
# transactions with the Groth16 proof verified on-chain in the SENDER frame.
#
# DEPLOYER_PK must be a genesis-prefunded key (ethereum-package well-known set,
# genesis_constants.star): faucet-funded keys hold ~0.001 ETH, and a tx whose
# gas_limit * max_fee exceeds the balance is either rejected at admission or,
# worse, admitted and then silently skipped by the builder forever.
#
# Gas limits are explicit twice over: eth_estimateGas fails on this devnet
# ("slot_number must be present" in the simulated context), and EIP-8037
# state-dimension accounting makes deploys cost ~214k + ~1,545 gas per byte of
# runtime, capped at 2^24 per tx (EIP-7825), hence the split Poseidon halves,
# each under ~10.7KB of runtime (see contracts/split_poseidon.py).
# Env: RPC_URL, DEPLOYER_PK, POOL_SENDER_PK.
set -euo pipefail
cd "$(dirname "$0")"
RPC=${RPC_URL:?set RPC_URL}
BN=../contracts
GAS="--gas-price 3000000000 --priority-gas-price 1000000000"
deployed() { grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}'; }
POOL_SENDER=$(cast wallet address --private-key "$POOL_SENDER_PK")
DEPLOYER=$(cast wallet address --private-key "$DEPLOYER_PK")
echo "deployer=$DEPLOYER  pool_sender=$POOL_SENDER"

echo "==> RecentRoots (EIP-8272 emulation)"
ROOTS=$(forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 3000000 --broadcast \
  src/RecentRoots.sol:RecentRoots | deployed)
echo "    roots=$ROOTS"
echo "==> Groth16Verifier (snarkjs, committed pot14 verifier)"
VERIFIER=$(forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 6000000 --broadcast \
  src/Groth16Verifier.sol:Groth16Verifier | deployed)
echo "    verifier=$VERIFIER"
# The Poseidon halves compile under the legacy-codegen `libsmall` profile:
# via-IR adds ~3KB of dispatch glue that pushes PoseidonT4 past the per-tx cap.
echo "==> PoseidonT3 (t=3 half, external library)"
T3=$(FOUNDRY_PROFILE=libsmall forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 12500000 --broadcast \
  src/PoseidonT3.sol:PoseidonT3 | deployed)
echo "    poseidonT3=$T3"
echo "==> PoseidonT4 (t=4 half, external library)"
T4=$(FOUNDRY_PROFILE=libsmall forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 16000000 --broadcast \
  src/PoseidonT4.sol:PoseidonT4 | deployed)
echo "    poseidonT4=$T4"
echo "==> ShieldedPool (join-split; links both Poseidon halves, creates its own NonceManager)"
# the contract path must precede the variadic --constructor-args, or forge
# create swallows it as another constructor argument.
POOL=$(forge create --root $BN --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 16700000 --broadcast \
  src/ShieldedPool.sol:ShieldedPool \
  --libraries "src/PoseidonT3.sol:PoseidonT3:$T3" \
  --libraries "src/PoseidonT4.sol:PoseidonT4:$T4" \
  --constructor-args "$POOL_SENDER" "$ROOTS" "$VERIFIER" | deployed)
# NonceManager is CREATE(pool, nonce=1); computed, since eth_call is unusable here
NONCES=$(cast compute-address "$POOL" --nonce 1 | awk '{print $NF}')
echo "    pool=$POOL  nonces=$NONCES"
echo "==> proof-gated APPROVE paymaster (50-byte runtime, see paymaster.py)"
# --gas-limit 1M: under EIP-8037 the code deposit alone is ~1,530 gas/byte.
PAYMASTER=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 1000000 \
  --create "$(python3 paymaster.py --initcode "$POOL")" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["contractAddress"])')
[ "$(cast code "$PAYMASTER" --rpc-url "$RPC")" = "$(python3 paymaster.py --runtime "$POOL")" ] \
  || { echo "paymaster runtime mismatch"; exit 1; }
# The pay frame's target is the payer, so the paymaster must hold ETH for gas.
# Its receive() guard (empty calldata -> STOP) accepts this plain transfer.
cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 100000 --value 1ether "$PAYMASTER" >/dev/null
echo "    paymaster=$PAYMASTER  funded=$(cast balance "$PAYMASTER" --rpc-url "$RPC" | cut -c1-4)...wei"

python3 - "$RPC" "$POOL" "$ROOTS" "$VERIFIER" "$NONCES" "$T3" "$T4" "$POOL_SENDER" "$PAYMASTER" <<'PY'
import json, sys
k = ["rpc","pool","roots","verifier","nonces","poseidonT3","poseidonT4","poolSender","paymaster"]
json.dump(dict(zip(k, sys.argv[1:])), open("deploy_config.json","w"), indent=1)
print("wrote deploy_config.json")
PY
echo "==> deployed. code sizes:"
for a in "$POOL" "$T3" "$T4" "$VERIFIER" "$ROOTS"; do
  echo "    $a $(cast code "$a" --rpc-url "$RPC" | wc -c) hex-chars"
done
echo
echo "next: fund POOL_SENDER, then shield/transfer/withdraw via pool_frametx.py,"
echo "threading _slot_transfer/_slot_withdraw from the receipt block numbers"
echo "(see REVIEW.md 'The live run')."
