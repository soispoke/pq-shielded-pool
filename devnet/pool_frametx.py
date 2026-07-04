#!/usr/bin/env python3
"""Run the BN254 shielded pool as an EIP-8141 frame-native application on the
Hegotá devnet (lambdaclass/ethrex hegota-devnet).

Each pool interaction rides a type-0x06 frame transaction:

  shield:   frames = [ VERIFY(target=sender, self-verify sig -> APPROVE),
                       SENDER(target=pool, value=amount, data=shield(inner)) ]
  transfer: frames = [ VERIFY(target=POOL_SENDER, self-verify),
                       SENDER(target=pool, value=0, data=transfer(Spend)) ]
  withdraw: same, data=withdraw(Spend, recipient)

The VERIFY frame is the reference self-verify pattern from
scripts/hegota-devnet/frametx_submit.py: the sender's default EOA code checks
the envelope's secp256k1 signature and grants execution+payment approval. The
SENDER frame then executes the pool call as tx.sender, so for spends the frame
sender MUST be the pool's pinned POOL_SENDER, which is exactly the on-chain
pinned-sender binding the pool already enforces.

The Groth16 proof is verified INSIDE the pool call (BN254 pairing precompiles),
so no attester is needed: the whole spend, proof check
included, executes on the devnet as an ordinary application frame.

What this integration does NOT do, and why (see REVIEW.md):
  * It does not put the two nullifiers in the transaction's `nonce_keys` (the
    protocol EIP-8250 spent set). The pool keeps its own NonceManager instead,
    because the devnet exposes no TXPARAM selector for `nonce_keys`, so an
    in-EVM VERIFY frame cannot bind the consumed key set to the proven
    nullifiers. `nonce_keys=[nf1,nf2]` is also not admitted by the public
    mempool (only `[0]` is). The `--protocol-nonces` flag builds that variant
    for a direct-to-builder submission experiment; it is expected to be
    rejected by the public RPC and is here to document the gap empirically.
  * It does not reference the root via the tx `recent_root_references`; the
    pool reads its own RecentRoots. The devnet does not deliver the slot to
    the EL yet, and no opcode exposes the refs to the pool.

Usage:
  pool_frametx.py <rpc> deploy-config.json fixture.json shield   <priv>
  pool_frametx.py <rpc> deploy-config.json fixture.json transfer <pool_sender_priv>
  pool_frametx.py <rpc> deploy-config.json fixture.json withdraw <pool_sender_priv>
"""
import json
import subprocess
import sys
import time
import urllib.request

from eth_keys import keys
from frametx import Frame, FrameSig, FrameTx


SPEND_TUPLE = "(bytes32,uint64,bytes32,bytes32,bytes32,bytes32,uint256,uint256,bytes32,uint256[2],uint256[2][2],uint256[2])"


def rpc(url, method, params):
    req = urllib.request.Request(
        url, headers={"content-type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r:
        raise RuntimeError(f"{method} -> {r['error']}")
    return r["result"]


def cast_calldata(sig, *args):
    """Build ABI calldata with foundry's cast (correct for the nested Spend
    struct without hand-rolling an ABI encoder)."""
    out = subprocess.run(["cast", "calldata", sig, *[str(a) for a in args]],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"cast calldata failed: {out.stderr}")
    return bytes.fromhex(out.stdout.strip().removeprefix("0x"))


def spend_args(entry):
    """The Spend tuple literal (for cast) from a fixture spend entry."""
    p = entry["proof"]
    pair = lambda v: "[" + ",".join(str(int(x, 16)) for x in v) + "]"
    pb = "[" + ",".join(pair(row) for row in p["pB"]) + "]"
    return (f'({entry["root"]},{entry["slot"]},{entry["nf1"]},{entry["nf2"]},'
            f'{entry["out_cm1"]},{entry["out_cm2"]},{entry["public_amount"]},'
            f'{entry["fee"]},{entry["ctx"]},{pair(p["pA"])},{pb},{pair(p["pC"])})')


def build_and_send(url, pk, pool, value, calldata, protocol_nonces=None):
    sender = int.from_bytes(pk.public_key.to_canonical_address(), "big")
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    nonce = int(rpc(url, "eth_getTransactionCount", [pk.public_key.to_checksum_address(), "latest"]), 16)
    blk = rpc(url, "eth_getBlockByNumber", ["latest", False])
    base_fee = int(blk.get("baseFeePerGas", "0x0"), 16)
    max_priority = 10**9
    max_fee = base_fee * 2 + max_priority
    nonce_keys = protocol_nonces if protocol_nonces else [0]
    nonce_seq = 0 if protocol_nonces else nonce

    def build():
        tx = FrameTx(
            chain_id=chain_id, nonce_keys=nonce_keys, nonce_seq=nonce_seq, sender=sender,
            frames=[
                # VERIFY stays under FRAME_TX_MAX_VERIFY_GAS = 100k, which caps
                # Σ(prefix frame gas) + signature cost; 100k exactly is rejected.
                Frame(mode=1, flags=0x03, target=sender, gas_limit=80_000, value=0, data=b""),
                # The SENDER frame is not part of the capped prefix. EIP-8037
                # state-dimension accounting inflates receipt gas ~2-4x over
                # Sepolia numbers, so size the execution frame generously.
                Frame(mode=2, flags=0, target=pool, gas_limit=10_000_000, value=value, data=calldata),
            ],
            signatures=[FrameSig(FrameSig.SECP256K1, sender, b"", b"")],
            max_priority_fee=max_priority, max_fee=max_fee)
        s = pk.sign_msg_hash(tx.sig_hash())
        sig = bytes([s.v + 27]) + s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big")
        tx.signatures = [FrameSig(FrameSig.SECP256K1, sender, b"", sig)]
        return tx

    tx = build()
    raw = "0x" + tx.raw().hex()
    print(f"  frame tx: sender={pk.public_key.to_checksum_address()} nonce_keys={nonce_keys} "
          f"raw_len={len(tx.raw())} sig_hash={tx.sig_hash().hex()[:18]}...")
    txhash = rpc(url, "eth_sendRawTransaction", [raw])
    print("  submitted:", txhash)
    for _ in range(30):
        rcpt = rpc(url, "eth_getTransactionReceipt", [txhash])
        if rcpt:
            status = int(rcpt.get('status', '0x0'), 16)
            print(f"  MINED block={int(rcpt['blockNumber'],16)} type={rcpt.get('type')} "
                  f"status={rcpt.get('status')} gasUsed={int(rcpt.get('gasUsed','0x0'),16)}")
            if status != 1:
                raise SystemExit(f'  tx reverted (status {rcpt.get("status")}); aborting')
            return rcpt
        time.sleep(2)
    raise SystemExit("  not mined within timeout")


def main():
    url, cfg_path, fix_path, op, priv = sys.argv[1:6]
    cfg = json.loads(open(cfg_path).read())
    fix = json.loads(open(fix_path).read())
    pool = int(cfg["pool"], 16)
    pk = keys.PrivateKey(bytes.fromhex(priv.removeprefix("0x")))
    protocol_nonces = None
    if "--protocol-nonces" in sys.argv and op in ("transfer", "withdraw"):
        e = fix[op]
        protocol_nonces = sorted([int(e["nf1"], 16), int(e["nf2"], 16)])  # strictly increasing

    if op == "shield":
        value = int(fix["shield_value"])
        calldata = cast_calldata("shield(bytes32)", fix["inner_a"])
        print(f"shield {value} wei via frame tx -> pool {cfg['pool']}")
        build_and_send(url, pk, pool, value, calldata)
    elif op == "transfer":
        e = fix["transfer"]
        e = {**e, "slot": cfg["_slot_transfer"]}
        calldata = cast_calldata(f"transfer({SPEND_TUPLE})", spend_args(e))
        print("join-split transfer via frame tx (proof verified on-chain in the SENDER frame)")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces)
    elif op == "withdraw":
        e = {**fix["withdraw"], "slot": cfg["_slot_withdraw"]}
        calldata = cast_calldata(f"withdraw({SPEND_TUPLE},address)", spend_args(e), fix["recipient"])
        print("join-split withdraw via frame tx")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces)
    else:
        raise SystemExit(f"unknown op {op}")


if __name__ == "__main__":
    main()
