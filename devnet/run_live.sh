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
# Env: RPC_URL, DEPLOYER_PK. (No POOL_SENDER_PK: the pool IS the frame-tx
# sender — one Yul contract is both the frame-0 VERIFY identity and the
# settlement target, per EIP-8250's `sender = PrivacyPool` shape.)
set -euo pipefail
cd "$(dirname "$0")"
RPC=${RPC_URL:?set RPC_URL}
BN=../contracts
GAS="--gas-price 3000000000 --priority-gas-price 1000000000"
deployed() { grep -oE 'Deployed to: 0x[0-9a-fA-F]{40}' | awk '{print $3}'; }
DEPLOYER=$(cast wallet address --private-key "$DEPLOYER_PK")
echo "deployer=$DEPLOYER"

echo "==> EnvelopeProbe (stateless frame-tx envelope reader, see EnvelopeProbe.yul)"
PROBE=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 500000 \
  --create "$(python3 probe.py --initcode)" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["contractAddress"])')
[ "$(cast code "$PROBE" --rpc-url "$RPC")" = "$(python3 probe.py --runtime)" ] \
  || { echo "probe runtime mismatch"; exit 1; }
echo "    probe=$PROBE"
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
echo "==> ShieldedPool (Yul, pool-as-sender; immutable tail = T3|T4|verifier|probe)"
# One Yul object (devnet/ShieldedPool.yul) is both the frame-0 VERIFY
# identity that APPROVEs execution and the settle target: tx.sender == the
# pool. Runtime ~4.8KB -> ~7.5M code-deposit gas under EIP-8037; 12M covers
# constructor execution (one root publish) with margin.
POOL_INIT=$(python3 yul_pool.py --initcode "$T3" "$T4" "$VERIFIER" "$PROBE")
POOL=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 12000000 \
  --create "$POOL_INIT" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["contractAddress"])')
# expected code via deployment simulation (cast call --create): the naive
# 0xfe-split is unsound for this object (a data segment trails the runtime).
[ "$(cast code "$POOL" --rpc-url "$RPC")" = "$(cast call --rpc-url "$RPC" --create "$POOL_INIT")" ] \
  || { echo "pool runtime mismatch"; exit 1; }
SOURCE_ID=$(cast call "$POOL" "sourceId()(bytes32)" --rpc-url "$RPC")
CHAIN_ID=$(cast chain-id --rpc-url "$RPC")
echo "    pool=$POOL  source_id=$SOURCE_ID"
echo "==> generating deployment-bound proofs"
python3 ../wallet/gen_smoke.py "--chain-id=$CHAIN_ID" "--source-id=$SOURCE_ID"
echo "==> proof-gated, sender-bound APPROVE paymaster (see paymaster.py)"
# --gas-limit 2M: the paymaster runtime is ~575 bytes (with the root-reference
# binding) and under EIP-8037 the code deposit alone is ~1,545 gas/byte, plus
# constructor execution; an underfunded deploy produces an empty (codeless)
# contract that the runtime-match check below then catches.
# pool||poolSender are appended as constructor args; the runtime binds
# TXPARAM(0x02)==poolSender, and the pool IS the sender, so both args are
# the pool address: only pool-as-sender spends can be sponsored.
PAYMASTER=$(cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 2000000 \
  --create "$(python3 paymaster.py --initcode "$POOL" "$POOL")" --json | python3 -c 'import json,sys;print(json.load(sys.stdin)["contractAddress"])')
[ "$(cast code "$PAYMASTER" --rpc-url "$RPC")" = "$(python3 paymaster.py --runtime "$POOL" "$POOL")" ] \
  || { echo "paymaster runtime mismatch"; exit 1; }
# The pay frame's target is the payer, so the paymaster must hold ETH for gas.
# Its receive() guard (empty calldata -> STOP) accepts this plain transfer.
cast send --rpc-url "$RPC" --private-key "$DEPLOYER_PK" $GAS --gas-limit 100000 --value 1ether "$PAYMASTER" >/dev/null
echo "    paymaster=$PAYMASTER  funded=$(cast balance "$PAYMASTER" --rpc-url "$RPC" | cut -c1-4)...wei"

# poolSender == pool: the pool is its own frame-tx sender.
python3 - "$RPC" "$POOL" "$PROBE" "$VERIFIER" "$T3" "$T4" "$POOL" "$PAYMASTER" "$SOURCE_ID" <<'PY'
import json, sys
k = ["rpc","pool","probe","verifier","poseidonT3","poseidonT4","poolSender","paymaster","sourceId"]
json.dump(dict(zip(k, sys.argv[1:])), open("deploy_config.json","w"), indent=1)
print("wrote deploy_config.json")
PY
echo "==> deployed. code sizes:"
for a in "$POOL" "$T3" "$T4" "$VERIFIER" "$PROBE"; do
  echo "    $a $(cast code "$a" --rpc-url "$RPC" | wc -c) hex-chars"
done
echo
echo "next: shield/transfer/withdraw via pool_frametx.py (spends default to"
echo "sender = the pool), threading _slot_transfer/_slot_withdraw from the"
echo "receipt block numbers (see REVIEW.md 'The live run')."
