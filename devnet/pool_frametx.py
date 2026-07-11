#!/usr/bin/env python3
"""Run the BN254 shielded pool as an EIP-8141 frame-native application on the
Hegotá devnet (lambdaclass/ethrex hegota-devnet).

Each pool interaction rides a type-0x06 frame transaction:

  shield:   frames = [ VERIFY(target=sender, self-verify sig -> APPROVE),
                       SENDER(target=pool, value=amount, data=shield(inner)) ]
  transfer: frames = [ VERIFY(target=POOL_SENDER, self-verify, execution),
                       VERIFY(target=paymaster, verifyProofOnly(Spend), payment),
                       SENDER(target=pool, value=0, data=transfer(Spend, feeRecipient)) ]
  withdraw: same, data=withdraw(Spend, recipient, feeRecipient)

The VERIFY frame is the reference self-verify pattern from
scripts/hegota-devnet/frametx_submit.py: the sender's default EOA code checks
the envelope's secp256k1 signature and grants execution+payment approval. The
SENDER frame then executes the pool call as tx.sender, so for spends the frame
sender MUST be the pool's pinned POOL_SENDER, which is exactly the on-chain
pinned-sender binding the pool already enforces.

The Groth16 proof is verified INSIDE the pool call (BN254 pairing precompiles),
so no attester is needed: the whole spend, proof check
included, executes on the devnet as an ordinary application frame.

Since the settle-only pool (step 2) transfers and withdraws are ALWAYS the
faithful shape: the pool keeps no spent set and no root history, so _spend
refuses to settle unless the transaction consumed exactly the proven
nullifiers as protocol keyed nonces and declared the proven root as its
recent-root reference. The faithful shape is the
EIP-8141 [only_verify, pay] grammar: an execution-scope self-verify frame
followed by a payment-scope pay frame targeting the proof-gated paymaster
(paymaster.py), which staticcalls pool.verifyProofOnly and APPROVEs payment only
if the proof is valid AND the envelope binds to POOL_SENDER (TXPARAM 0x02),
nonce_seq == 0, exactly three frames, nonce_keys == sorted{nf1, nf2}
(NONCEKEYLOAD), and one declared EIP-8272 recent-root reference carrying the
pool's source_id and the spend's proven root (RECENTROOTREFLOAD 0xB5). The
faithful tx therefore declares `recent_root_references = [[source_id, slot,
root]]`, with slot the consensus slot of the block that published the root
(derived from that block's timestamp the same way ethrex's derivedSlotTime
knob does); the protocol validates the reference at admission and at block
execution, which makes root recency protocol-enforced. The pool re-binds the
same envelope facts in the SENDER frame via EnvelopeProbe.yul. The
sender bind is what stops a costless dummy-input proof from draining the funded
paymaster (see REVIEW.md 2026-07-10); the proof is checked before any approval.
verifySpend
~243k fits MAX_VERIFY_GAS once raised (500k on the devnet as of 2026-07-08).
verifyProofOnly reads no RecentRoots storage and the paymaster is SLOAD-free,
so the pay frame does not trip the observer's StorageReadNonSender ban, and
since 2026-07-08 non-zero nonce_keys are public-mempool admissible, so the
faithful spend submits through the public RPC. The paymaster must be funded:
it is the payer.

Usage:
  pool_frametx.py <rpc> deploy-config.json fixture.json shield   <priv>
  pool_frametx.py <rpc> deploy-config.json fixture.json transfer <pool_sender_priv> [--proof-in-verify]
  pool_frametx.py <rpc> deploy-config.json fixture.json withdraw <pool_sender_priv> [--proof-in-verify]
"""
import json
import subprocess
import sys
import time
import urllib.request

from eth_keys import keys
from frametx import Frame, FrameSig, FrameTx


SPEND_TUPLE = "(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint256,uint256,bytes32,uint256[2],uint256[2][2],uint256[2])"


def rpc(url, method, params):
    req = urllib.request.Request(
        url, headers={"content-type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r:
        raise RuntimeError(f"{method} -> {r['error']}")
    return r["result"]


def simulate(url, raw):
    """Dry-run a built frame tx via ethrex_simulateFrameTransaction (the
    ethrex_ namespace, ethrex >= v17, commit e7e495f): the frame-native
    counterpart to eth_estimateGas, which cannot represent a multi-frame tx.
    Runs the mempool validation prefix and, if it passes, a full read-only
    multi-frame execution at head. Returns the result dict, or None if the
    endpoint does not expose the method (-32601). Raises on any other RPC
    error (malformed tx). A tx over the per-tx gas cap comes back as a result
    with valid=False, not an error."""
    req = urllib.request.Request(
        url, headers={"content-type": "application/json"},
        data=json.dumps({"jsonrpc": "2.0", "id": 1,
                         "method": "ethrex_simulateFrameTransaction",
                         "params": [raw]}).encode())
    r = json.loads(urllib.request.urlopen(req, timeout=20).read())
    if "error" in r:
        if r["error"].get("code") == -32601:
            return None
        raise SystemExit(f"  simulate RPC error: {r['error']}")
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
    return (f'({entry["root"]},{entry["domain"]},{entry["nf1"]},{entry["nf2"]},'
            f'{entry["out_cm1"]},{entry["out_cm2"]},{entry["public_amount"]},'
            f'{entry["fee"]},{entry["ctx"]},{pair(p["pA"])},{pb},{pair(p["pC"])})')


def recent_root_ref(url, cfg, e):
    """The pre-encoded EIP-8272 envelope reference [source_id, slot, root] for
    the spend's root. `e["slot"]` is the block number that published the root
    (threaded in as cfg _slot_transfer/_slot_withdraw from the receipt); its
    consensus slot is derived from that block's timestamp exactly as ethrex's
    derivedSlotTime knob does: (timestamp - genesis_timestamp) / seconds_per_slot
    (6s on the devnet, override with cfg["secondsPerSlot"]). The paymaster binds
    source_id and root (RECENTROOTREFLOAD); the protocol enforces the recency
    window and the committed entry at admission and at block execution."""
    from frametx import rlp_bytes, rlp_int, rlp_list
    pub_block = int(e["slot"])
    ts = int(rpc(url, "eth_getBlockByNumber", [hex(pub_block), False])["timestamp"], 16)
    genesis_ts = int(rpc(url, "eth_getBlockByNumber", ["0x0", False])["timestamp"], 16)
    slot = (ts - genesis_ts) // int(cfg.get("secondsPerSlot", 6))
    source_id = bytes.fromhex(cfg["sourceId"].removeprefix("0x"))
    root = bytes.fromhex(e["root"].removeprefix("0x"))
    return rlp_list([rlp_bytes(source_id), rlp_int(slot), rlp_bytes(root)])


def build_and_send(url, pk, pool, value, calldata, protocol_nonces=None, proof_verify=None,
                   recent_root_refs=None, dry_run=False):
    sender = int.from_bytes(pk.public_key.to_canonical_address(), "big")
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    nonce = int(rpc(url, "eth_getTransactionCount", [pk.public_key.to_checksum_address(), "latest"]), 16)
    blk = rpc(url, "eth_getBlockByNumber", ["latest", False])
    base_fee = int(blk.get("baseFeePerGas", "0x0"), 16)
    max_priority = 10**9
    max_fee = base_fee * 2 + max_priority
    nonce_keys = protocol_nonces if protocol_nonces else [0]
    nonce_seq = 0 if protocol_nonces else nonce

    def build(sender_gas=10_000_000):
        if proof_verify:
            # The FAITHFUL shape, EIP-8141 [only_verify, pay] grammar (validated
            # live via OpenSponsor on 2026-07-05). Frame 0 self-verifies for the
            # EXECUTION scope only (0x02, target sender). Frame 1 is the pay
            # frame (0x01, PAYMENT scope) targeting the proof-gated paymaster,
            # which staticcalls pool.verifyProofOnly and APPROVEs payment only on
            # a valid proof; the paymaster must be funded (it is the payer).
            # verifyProofOnly reads no RecentRoots storage and the paymaster is
            # SLOAD-free, so the pay frame no longer trips the observer's
            # StorageReadNonSender ban (see REVIEW.md); it still submits
            # builder-direct, which it must anyway for nonce_keys=[nf1,nf2].
            paymaster, vcalldata = proof_verify
            frames = [
                Frame(mode=1, flags=0x02, target=sender, gas_limit=20_000, value=0, data=b""),
                Frame(mode=1, flags=0x01, target=paymaster, gas_limit=300_000, value=0, data=vcalldata),
            ]
        else:
            # Today's shape: one self-verify frame approves execution AND payment
            # (0x03), so the sender is its own payer. VERIFY stays under
            # FRAME_TX_MAX_VERIFY_GAS = 100k, which caps Σ(prefix frame gas) +
            # signature cost; 100k exactly is rejected.
            frames = [Frame(mode=1, flags=0x03, target=sender, gas_limit=80_000, value=0, data=b"")]
        # The SENDER frame is not part of the capped prefix. It starts
        # generous (EIP-8037 state-dimension accounting inflates gas ~2-4x over
        # Sepolia numbers) and is then sized down from the simulated per-frame
        # gas below, when the endpoint exposes ethrex_simulateFrameTransaction.
        frames.append(Frame(mode=2, flags=0, target=pool, gas_limit=sender_gas,
                            value=value, data=calldata))
        tx = FrameTx(
            chain_id=chain_id, nonce_keys=nonce_keys, nonce_seq=nonce_seq, sender=sender,
            frames=frames,
            signatures=[FrameSig(FrameSig.SECP256K1, sender, b"", b"")],
            max_priority_fee=max_priority, max_fee=max_fee,
            recent_root_refs=recent_root_refs)
        s = pk.sign_msg_hash(tx.sig_hash())
        sig = bytes([s.v + 27]) + s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big")
        tx.signatures = [FrameSig(FrameSig.SECP256K1, sender, b"", sig)]
        return tx

    tx = build()
    raw = "0x" + tx.raw().hex()

    # Dry-run first: pre-check validity, report the resolved payer, and size
    # the (uncapped) SENDER frame from the simulated gas. Degrades to the
    # default limits on an endpoint that does not expose the ethrex_ namespace.
    sim = simulate(url, raw)
    if dry_run:
        if sim is None:
            print("  dry-run: ethrex_simulateFrameTransaction unavailable on this endpoint")
        else:
            per = ", ".join(f"f{i}={int(f['gasUsed'],16):,}" for i, f in enumerate(sim.get("frames") or []))
            g = int(sim["gasUsed"], 16) if sim.get("gasUsed") else None
            print(f"  dry-run: valid={sim.get('valid')}  shape={sim.get('prefixShape')}  "
                  f"payer={sim.get('payer')}  status={sim.get('executionStatus')}")
            print(f"           violation={sim.get('violation')}")
            if g is not None:
                print(f"           gas={g:,}  ({per})")
        return
    eff = sim  # the simulation the send is gated on (resized one if adopted)
    if sim is None:
        print("  simulate: ethrex_simulateFrameTransaction unavailable here; default gas limits")
    elif sim.get("valid"):
        per = ", ".join(f"f{i}={int(f['gasUsed'],16):,}" for i, f in enumerate(sim.get("frames") or []))
        print(f"  simulate: valid  shape={sim.get('prefixShape')}  payer={sim.get('payer')}  "
              f"gas={int(sim['gasUsed'],16):,}  ({per})")
        used = int(sim["frames"][-1]["gasUsed"], 16)
        sized = used + used // 4  # measured + 25% for state-gas variance at a later block
        tx2 = build(sender_gas=sized)
        raw2 = "0x" + tx2.raw().hex()
        s2 = simulate(url, raw2)
        if s2 and s2.get("valid"):
            tx, raw, eff = tx2, raw2, s2
            print(f"  sized SENDER frame to {sized:,} gas (measured {used:,} + 25%)")
    elif proof_verify:
        print(f"  simulate: prefix not mempool-admissible ({sim.get('violation')}); "
              "expected for the faithful shape, attempting builder-direct anyway")
    else:
        raise SystemExit(f"  simulate: INVALID ({sim.get('violation')}); not sending")

    # Refuse to send when the SENDER frame reverts in simulation. The common
    # cause is a transfer landing in the same block the shield published the
    # root, so roots.check sees current == slot and reverts RootNotRecentForPool
    # (the root is referenceable only from the next block). Without this guard
    # the SENDER frame is sized from that cheap revert and the live tx runs out
    # of gas. Only gate when the sim produced an execution result.
    if eff and eff.get("executionStatus") and eff["executionStatus"] != "success":
        raise SystemExit(f"  simulate: SENDER frame reverts "
                         f"({eff.get('executionError') or eff['executionStatus']}); not sending "
                         "(if root-not-recent, retry one block later)")

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
    sender_address = pk.public_key.to_checksum_address()
    # --proof-in-verify implies protocol nonces: the ProofPaymaster binds the
    # envelope's nonce_keys to the proven nullifiers (NONCEKEYLOAD), so the two
    # nullifiers MUST be the transaction's key set.
    # settle-only pool: every spend is the faithful shape (the flag remains
    # accepted for compatibility but is implied)
    proof_in_verify = op in ("transfer", "withdraw")
    dry = "--dry-run" in sys.argv
    protocol_nonces = None
    if ("--protocol-nonces" in sys.argv or proof_in_verify) and op in ("transfer", "withdraw"):
        e = fix[op]
        protocol_nonces = sorted([int(e["nf1"], 16), int(e["nf2"], 16)])  # strictly increasing

    def verify_frame(e):
        """The faithful-shape VERIFY frame: ProofPaymaster target, verifyProofOnly
        data. The paymaster binds nonce_keys == {nf1, nf2}, the declared
        recent-root reference (pool source_id + proven root), and staticcalls
        verifyProofOnly (proof + canonicity, no RecentRoots read) so the frame
        reads no non-sender storage; the protocol enforces root recency via the
        reference, and the SENDER frame's verifySpend re-checks the pool's own
        emulation as a belt."""
        if not proof_in_verify:
            return None
        return (int(cfg["paymaster"], 16),
                cast_calldata(f"verifyProofOnly({SPEND_TUPLE})", spend_args(e)))

    if op == "shield":
        value = int(fix["shield_value"])
        calldata = cast_calldata("shield(bytes32)", fix["inner_a"])
        print(f"shield {value} wei via frame tx -> pool {cfg['pool']}")
        build_and_send(url, pk, pool, value, calldata, dry_run=dry)
    elif op == "transfer":
        e = fix["transfer"]
        fee_recipient = cfg["paymaster"] if proof_in_verify else sender_address
        refs = [recent_root_ref(url, cfg, {"slot": cfg["_slot_transfer"], "root": e["root"]})]
        calldata = cast_calldata(f"transfer({SPEND_TUPLE},address)", spend_args(e), fee_recipient)
        print("join-split transfer via frame tx (proof verified on-chain in the SENDER frame)")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces, verify_frame(e), refs, dry_run=dry)
    elif op == "withdraw":
        e = fix["withdraw"]
        fee_recipient = cfg["paymaster"] if proof_in_verify else sender_address
        refs = [recent_root_ref(url, cfg, {"slot": cfg["_slot_withdraw"], "root": e["root"]})]
        calldata = cast_calldata(f"withdraw({SPEND_TUPLE},address,address)", spend_args(e),
                                 fix["recipient"], fee_recipient)
        print("join-split withdraw via frame tx")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces, verify_frame(e), refs, dry_run=dry)
    else:
        raise SystemExit(f"unknown op {op}")


if __name__ == "__main__":
    main()
