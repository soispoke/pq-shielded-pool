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

Usage (append --dry-run to any to simulate without submitting):
  pool_frametx.py <rpc> deploy-config.json fixture.json shield   <priv>
  pool_frametx.py <rpc> deploy-config.json fixture.json transfer <pool_sender_priv> [--paymaster 0x...]
  pool_frametx.py <rpc> deploy-config.json fixture.json withdraw <pool_sender_priv> [--paymaster 0x...]
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


RECENT_ROOT_ADDRESS = "0x0000000000000000000000000000000000008272"
RECENT_ROOT_LENGTH = 8192


def _keccak(b):
    from eth_hash.auto import keccak
    return keccak(b)


def recent_root_ref(url, cfg, e):
    """The pre-encoded EIP-8272 envelope reference [source_id, slot, root] for
    the spend's root. `e["slot"]` is the block number that published the root
    (threaded in as cfg _slot_transfer/_slot_withdraw from the receipt); its
    consensus slot is derived from that block's timestamp the way ethrex's
    derivedSlotTime knob does: (timestamp - genesis_timestamp) / seconds_per_slot.

    ethrex keys the derivation on ChainConfig.genesis_timestamp and
    seconds_per_slot, which need not equal EL block 0's timestamp or a
    hardcoded 6s. We prefer explicit cfg values and fall back to block 0 / 6s,
    then VERIFY the derived reference against the committed predeploy entry
    before returning it. A wrong slot (mismatched genesis/seconds) fails here
    loudly instead of silently producing an unadmittable transaction. The
    paymaster binds source_id and root (RECENTROOTREFLOAD); the protocol
    enforces the recency window and this same committed entry."""
    from frametx import rlp_bytes, rlp_int, rlp_list
    pub_block = int(e["slot"])
    ts = int(rpc(url, "eth_getBlockByNumber", [hex(pub_block), False])["timestamp"], 16)
    genesis_ts = int(cfg["genesisTimestamp"]) if "genesisTimestamp" in cfg \
        else int(rpc(url, "eth_getBlockByNumber", ["0x0", False])["timestamp"], 16)
    slot = (ts - genesis_ts) // int(cfg.get("secondsPerSlot", 6))
    source_id = bytes.fromhex(cfg["sourceId"].removeprefix("0x"))
    root = bytes.fromhex(e["root"].removeprefix("0x"))

    # Self-check: the committed entry the protocol will validate against must
    # already exist for this (source_id, slot, root). One definition, shared
    # with RecentRootReference::{entry_hash, storage_key} in ethrex-common.
    entry = _keccak(_keccak(b"RECENT_ROOT_ENTRY") + source_id + slot.to_bytes(8, "big") + root)
    skey = _keccak(_keccak(b"RECENT_ROOT_STORAGE") + source_id + (slot % RECENT_ROOT_LENGTH).to_bytes(8, "big"))
    stored = rpc(url, "eth_getStorageAt", [RECENT_ROOT_ADDRESS, "0x" + skey.hex(), "latest"])
    if bytes.fromhex(stored.removeprefix("0x").rjust(64, "0")) != entry:
        raise SystemExit(
            f"  recent-root ref self-check failed: derived slot {slot} for block {pub_block} "
            f"has no committed entry at the predeploy. Check cfg genesisTimestamp/secondsPerSlot "
            f"against the chain's ChainConfig; a wrong slot would be rejected as "
            f"FrameTxRecentRootNotCommitted.")
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
        # Sepolia numbers). Non-spends are sized down from the simulated
        # per-frame gas below; spends keep the generous default, because an
        # OOG settle frame after payment approval burns the notes.
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
        # A spend that mines with a reverting SENDER frame still consumes its
        # nullifiers as protocol keyed nonces at payment approval but never
        # inserts the outputs: the notes are burned for good. The SENDER-revert
        # guard below is the only pre-send defense, so refuse to fly blind on
        # spends. A shield that reverts loses nothing (the deposit stays with
        # the sender), so shields may proceed on default limits.
        if protocol_nonces:
            raise SystemExit(
                "  simulate: ethrex_simulateFrameTransaction unavailable here; refusing to "
                "send a nullifier-consuming spend without a pre-send simulation "
                "(a mined tx whose SENDER frame reverts burns the spent notes)")
        print("  simulate: ethrex_simulateFrameTransaction unavailable here; default gas limits")
    elif sim.get("valid"):
        # gasUsed (top-level and per-frame) is a hex string on success, but the
        # node may return null; guard so a cosmetic gap never aborts a valid send.
        hexint = lambda v: int(v, 16) if isinstance(v, str) else None
        per = ", ".join(f"f{i}={hexint(f.get('gasUsed'))}" for i, f in enumerate(sim.get("frames") or []))
        total = hexint(sim.get("gasUsed"))
        print(f"  simulate: valid  shape={sim.get('prefixShape')}  payer={sim.get('payer')}  "
              f"gas={total}  ({per})")
        # Down-size the SENDER frame from the simulated gas ONLY for
        # non-spends. EIP-8037 state-dimension accounting varies 2-4x across
        # blocks, so measured + 25% is not a safe margin when the failure is
        # irreversible: a spend whose SENDER frame OOGs after payment approval
        # burns the notes (nullifiers consumed, outputs never inserted). For
        # spends the generous default stays; the payer's worst case is
        # prepaying more gas, refunded on success.
        used = hexint((sim.get("frames") or [{}])[-1].get("gasUsed"))
        if used is not None and not protocol_nonces:
            sized = used + used // 4  # measured + 25% for state-gas variance at a later block
            tx2 = build(sender_gas=sized)
            raw2 = "0x" + tx2.raw().hex()
            s2 = simulate(url, raw2)
            if s2 and s2.get("valid"):
                tx, raw, eff = tx2, raw2, s2
                print(f"  sized SENDER frame to {sized:,} gas (measured {used:,} + 25%)")
    else:
        # Since the 2026-07-08 devnet update, non-zero keyed nonces are
        # public-mempool admissible, so the faithful shape is expected to
        # simulate VALID. An invalid simulation is a real defect (unfunded
        # paymaster, wrong nonce_keys, stale root, bad calldata), not the old
        # "expected inadmissibility": abort rather than broadcast a doomed tx
        # whose prefix failure the SENDER-revert guard below cannot catch.
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
                msg = f'  tx reverted (status {rcpt.get("status")}); aborting'
                if protocol_nonces:
                    msg += ("\n  WARNING: the SENDER frame reverted after payment approval, so the"
                            "\n  nullifiers were consumed as protocol keyed nonces and the spent"
                            "\n  notes are burned; the output notes were never inserted.")
                raise SystemExit(msg)
            return rcpt
        time.sleep(2)
    raise SystemExit("  not mined within timeout")


def main():
    url, cfg_path, fix_path, op, priv = sys.argv[1:6]
    cfg = json.loads(open(cfg_path).read())
    fix = json.loads(open(fix_path).read())
    pool = int(cfg["pool"], 16)
    pk = keys.PrivateKey(bytes.fromhex(priv.removeprefix("0x")))
    dry = "--dry-run" in sys.argv
    paymaster = cfg.get("paymaster")
    if "--paymaster" in sys.argv:
        i = sys.argv.index("--paymaster")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--paymaster requires an address")
        paymaster = sys.argv[i + 1]
    for arg in sys.argv[6:]:
        if arg.startswith("--paymaster="):
            paymaster = arg.split("=", 1)[1]
    if op in ("transfer", "withdraw"):
        if not paymaster:
            raise SystemExit("spend requires cfg.paymaster or --paymaster 0x...")
        try:
            paymaster_int = int(paymaster, 16)
        except ValueError:
            raise SystemExit(f"invalid paymaster address: {paymaster}") from None
        if paymaster_int == 0 or paymaster_int >= 1 << 160:
            raise SystemExit(f"invalid paymaster address: {paymaster}")
    else:
        paymaster_int = None

    def spend_setup(op_name):
        """Protocol nonces, verify frame, and recent-root reference for a
        settle-only spend (always the faithful shape). The ProofPaymaster is
        the pay-frame target and payer: it binds nonce_keys == {nf1, nf2}
        (NONCEKEYLOAD) and the declared recent-root reference (pool source_id +
        proven root, RECENTROOTREFLOAD), and staticcalls verifyProofOnly (proof
        + canonicity, no storage read). The pool re-binds the same envelope
        facts in the SENDER frame via EnvelopeProbe."""
        e = fix[op_name]
        protocol_nonces = sorted([int(e["nf1"], 16), int(e["nf2"], 16)])  # strictly increasing
        verify = (paymaster_int,
                  cast_calldata(f"verifyProofOnly({SPEND_TUPLE})", spend_args(e)))
        refs = [recent_root_ref(url, cfg, {"slot": cfg[f"_slot_{op_name}"], "root": e["root"]})]
        return e, protocol_nonces, verify, refs

    if op == "shield":
        value = int(fix["shield_value"])
        calldata = cast_calldata("shield(bytes32)", fix["inner_a"])
        print(f"shield {value} wei via frame tx -> pool {cfg['pool']}")
        build_and_send(url, pk, pool, value, calldata, dry_run=dry)
    elif op == "transfer":
        e, protocol_nonces, verify, refs = spend_setup("transfer")
        calldata = cast_calldata(f"transfer({SPEND_TUPLE},address)", spend_args(e), paymaster)
        print(f"join-split transfer via faithful frame tx (payer {paymaster}, proof verified on-chain)")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces, verify, refs, dry_run=dry)
    elif op == "withdraw":
        e, protocol_nonces, verify, refs = spend_setup("withdraw")
        calldata = cast_calldata(f"withdraw({SPEND_TUPLE},address,address)", spend_args(e),
                                 fix["recipient"], paymaster)
        print(f"join-split withdraw via faithful frame tx (payer {paymaster})")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces, verify, refs, dry_run=dry)
    else:
        raise SystemExit(f"unknown op {op}")


if __name__ == "__main__":
    main()
