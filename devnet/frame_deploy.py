#!/usr/bin/env python3
"""Deploy a contract via an EIP-8141 frame transaction (SENDER frame CREATE).

This devnet executes state changes only inside post-approval SENDER frames, and
its eth_estimateGas is unusable, so contracts are deployed by a frame tx whose
SENDER frame carries the init code with an empty target (a CREATE), preceded by
the reference self-verify VERIFY frame.

  frame_deploy.py <rpc> <deployer_priv> <init_code_hex> [gas_limit]

Prints the created address and the tx hash.
"""
import json
import sys
import time
import urllib.request

from eth_hash.auto import keccak
from eth_keys import keys
from frametx import Frame, FrameSig, FrameTx, rlp_bytes, rlp_int, rlp_list


def rpc(url, method, params):
    req = urllib.request.Request(
        url, headers={"content-type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r:
        raise RuntimeError(f"{method} -> {r['error']}")
    return r["result"]


def create_address(sender_bytes, nonce):
    item = rlp_list([rlp_bytes(sender_bytes), rlp_int(nonce)])
    return "0x" + keccak(item)[12:].hex()


def main():
    url, priv, init_hex = sys.argv[1], sys.argv[2], sys.argv[3]
    gas_limit = int(sys.argv[4]) if len(sys.argv) > 4 else 8_000_000
    init = bytes.fromhex(init_hex.removeprefix("0x"))
    pk = keys.PrivateKey(bytes.fromhex(priv.removeprefix("0x")))
    sender = int.from_bytes(pk.public_key.to_canonical_address(), "big")
    sender_bytes = pk.public_key.to_canonical_address()

    chain_id = int(rpc(url, "eth_chainId", []), 16)
    nonce = int(rpc(url, "eth_getTransactionCount", [pk.public_key.to_checksum_address(), "latest"]), 16)
    blk = rpc(url, "eth_getBlockByNumber", ["latest", False])
    base_fee = int(blk.get("baseFeePerGas", "0x0"), 16)
    max_priority = 10**9
    max_fee = base_fee * 2 + max_priority
    # a SENDER frame with an empty target and init code data performs a CREATE
    tx = FrameTx(
        chain_id=chain_id, nonce_keys=[0], nonce_seq=nonce, sender=sender,
        frames=[
            Frame(mode=1, flags=0x03, target=sender, gas_limit=80_000, value=0, data=b""),
            Frame(mode=2, flags=0, target=None, gas_limit=gas_limit, value=0, data=init),
        ],
        signatures=[FrameSig(FrameSig.SECP256K1, sender, b"", b"")],
        max_priority_fee=max_priority, max_fee=max_fee)
    s = pk.sign_msg_hash(tx.sig_hash())
    sig = bytes([s.v + 27]) + s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big")
    tx.signatures = [FrameSig(FrameSig.SECP256K1, sender, b"", sig)]

    predicted = create_address(sender_bytes, nonce)
    txhash = rpc(url, "eth_sendRawTransaction", ["0x" + tx.raw().hex()])
    print(f"  submitted {txhash} (predicted CREATE addr {predicted})")
    for _ in range(30):
        rcpt = rpc(url, "eth_getTransactionReceipt", [txhash])
        if rcpt:
            ca = rcpt.get("contractAddress")
            print(f"  MINED block={int(rcpt['blockNumber'],16)} status={rcpt.get('status')} "
                  f"contractAddress={ca}")
            addr = ca or predicted
            code = rpc(url, "eth_getCode", [addr, "latest"])
            print(f"  code@{addr}: {len(code)//2-1} bytes")
            print(addr)
            return 0 if rcpt.get("status") == "0x1" else 1
        time.sleep(2)
    print("  not mined"); return 1


if __name__ == "__main__":
    sys.exit(main())
