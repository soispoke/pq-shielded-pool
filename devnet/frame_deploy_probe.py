#!/usr/bin/env python3
"""Deploy via the DeploySelfVerify frame shape: a mode-0 DEFAULT deploy frame
(target=None, data=initcode) followed by a self-verify VERIFY frame. The whole
prefix (deploy + verify + sig) must be <= FRAME_TX_MAX_VERIFY_GAS = 100_000, so
this only works for tiny contracts (e.g. a CREATE2 factory).

  deploy_frame_create.py <rpc> <priv> <init_hex> [deploy_gas] [verify_gas]
"""
import json, sys, time, urllib.request
from eth_keys import keys
from frametx import Frame, FrameSig, FrameTx

def rpc(url, m, p):
    req = urllib.request.Request(url, headers={"content-type":"application/json"},
        data=json.dumps({"jsonrpc":"2.0","id":1,"method":m,"params":p}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r: raise RuntimeError(f"{m} -> {r['error']}")
    return r["result"]

def main():
    url, priv, init_hex = sys.argv[1:4]
    deploy_gas = int(sys.argv[4]) if len(sys.argv)>4 else 70_000
    verify_gas = int(sys.argv[5]) if len(sys.argv)>5 else 20_000
    init = bytes.fromhex(init_hex.removeprefix("0x"))
    pk = keys.PrivateKey(bytes.fromhex(priv.removeprefix("0x")))
    sender = int.from_bytes(pk.public_key.to_canonical_address(), "big")
    chain_id = int(rpc(url,"eth_chainId",[]),16)
    nonce = int(rpc(url,"eth_getTransactionCount",[pk.public_key.to_checksum_address(),"latest"]),16)
    base = int(rpc(url,"eth_getBlockByNumber",["latest",False]).get("baseFeePerGas","0x0"),16)
    tx = FrameTx(chain_id=chain_id, nonce_keys=[0], nonce_seq=nonce, sender=sender,
        frames=[
            Frame(mode=0, flags=0x00, target=None, gas_limit=deploy_gas, value=0, data=init),
            Frame(mode=1, flags=0x03, target=sender, gas_limit=verify_gas, value=0, data=b""),
        ],
        signatures=[FrameSig(FrameSig.SECP256K1, sender, b"", b"")],
        max_priority_fee=10**9, max_fee=base*2+10**9)
    s = pk.sign_msg_hash(tx.sig_hash())
    tx.signatures=[FrameSig(FrameSig.SECP256K1, sender, b"", bytes([s.v+27])+s.r.to_bytes(32,"big")+s.s.to_bytes(32,"big"))]
    txhash = rpc(url,"eth_sendRawTransaction",["0x"+tx.raw().hex()])
    print("  submitted", txhash)
    for _ in range(30):
        rc = rpc(url,"eth_getTransactionReceipt",[txhash])
        if rc:
            ca = rc.get("contractAddress")
            print(f"  MINED block={int(rc['blockNumber'],16)} status={rc.get('status')} contractAddress={ca} gasUsed={int(rc.get('gasUsed','0x0'),16)}")
            if ca:
                print("  code bytes:", len(rpc(url,"eth_getCode",[ca,"latest"]))//2-1)
            return 0 if rc.get("status")=="0x1" else 1
        time.sleep(2)
    print("  not mined"); return 1

if __name__=="__main__":
    sys.exit(main())
