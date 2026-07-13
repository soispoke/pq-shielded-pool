#!/usr/bin/env python3
"""Run the BN254 shielded pool as an EIP-8141 frame-native application on the
Hegotá devnet (lambdaclass/ethrex hegota-devnet).

Each pool interaction rides a type-0x06 frame transaction:

  shield:   frames = [ VERIFY(target=sender, self-verify sig -> APPROVE),
                       SENDER(target=pool, value=amount, data=shield(inner)) ]
  transfer: frames = [ VERIFY(target=pool, proof authorization, execution),
                       VERIFY(target=paymaster, bound Spend carrier, payment),
                       SENDER(target=pool, value=0, data=transfer(Spend, feeRecipient)) ]
  withdraw: same, data=withdraw(Spend, recipient, feeRecipient)

For spends the pool IS the transaction sender (EIP-8250's intended shape:
FrameTx { sender = PrivacyPool, nonce_keys = [nA, nB], nonce_seq = 0 }). The
pool's frame-0 VERIFY (empty calldata) authenticates the proof, exact
nonce-key set, recent-root reference and settlement data before approving
execution; the SENDER frame is then a self-call that settles. Every
nullifier gets one EIP-8250 namespace under the pool's address without an
operator-held key, so spends with disjoint nullifiers are includable in the
same block. Spends default to sender = cfg pool; --sender overrides (for
adversarial vectors or legacy split-sender deployments).

The Groth16 proof is verified INSIDE the pool call (BN254 pairing precompiles),
so no attester is needed: the whole spend, proof check
included, executes on the devnet as an ordinary application frame.

Since the settle-only pool (step 2) transfers and withdraws are ALWAYS the
faithful shape: the pool keeps no spent set and no root history, so _spend
refuses to settle unless the transaction consumed exactly the proven
nullifiers as protocol keyed nonces and declared the proven root as its
recent-root reference. The faithful shape is the
EIP-8141 [only_verify, pay] grammar: an execution-scope self-verify frame
followed by a payment-scope pay frame targeting the bounded paymaster
(paymaster.py). The paymaster authenticates the successful proof-authorized
frame 0, binds its Spend carrier byte-for-byte to settlement, requires the
proof-bound fee to cover TXPARAM(0x06), and APPROVEs payment only if the
envelope binds to POOL_SENDER (TXPARAM 0x02),
nonce_seq == 0, exactly three frames, nonce_keys == sorted{nf1, nf2}
(NONCEKEYLOAD), and one declared EIP-8272 recent-root reference carrying the
pool's source_id and the spend's proven root (RECENTROOTREFLOAD 0xB5). The
faithful tx therefore declares `recent_root_references = [[source_id, slot,
root]]`, with slot the consensus slot of the block that published the root
(derived from that block's timestamp the same way ethrex's derivedSlotTime
knob does); the protocol validates the reference at admission and at block
execution, which makes root recency protocol-enforced. The pool re-binds the
same envelope facts in the SENDER frame via EnvelopeProbe.yul. The
sender bind is what lets the paymaster rely on frame 0 rather than perform a
second Groth16 check. The preferred immutable dispatcher verifies inline and
the paymaster is SLOAD-free, so neither frame trips the observer's
StorageReadNonSender ban. The sender's ~250k proof check plus the paymaster's
bounded envelope work fit MAX_VERIFY_GAS=500k, and
since 2026-07-08 non-zero nonce_keys are public-mempool admissible, so the
faithful spend submits through the public RPC. The paymaster must be funded:
it is the payer.

Usage (append --dry-run to any to simulate without submitting):
  pool_frametx.py <rpc> deploy-config.json fixture.json shield   <priv>
  pool_frametx.py <rpc> deploy-config.json fixture.json transfer <signer_priv> [--sender 0x...] [--paymaster 0x...]
  pool_frametx.py <rpc> deploy-config.json fixture.json withdraw <signer_priv> [--sender 0x...] [--paymaster 0x...]

`--sender` decouples the authenticated frame sender from the outer signature's
signer. Spends default it to the pool itself: the pool's VERIFY frame grants
execution authority, while any submitter supplies the one outer signature the
current proof-paymaster grammar requires.

`--max-fee-per-gas` and `--max-priority-fee-per-gas` help construct repeatable
fee-boundary tests. The builder prints the exact TXPARAM(0x06) value, including
frame limits, intrinsic and envelope calldata gas, signature verification, and
recent-root-reference gas, using ethrex's current formula.

Adversarial-suite flags (spends only; see devnet/vectors/ for archived runs):
`--flip-proof` flips one bit in pA[0] in both proof-bearing frames, producing a
reproducible invalid-proof vector without hand-editing a fixture.
`--nonce-keys 0x..,0x..` replaces the protocol nonce keys, for wrong-key
rejection vectors. `--settle-gas N` overrides the pinned 10M settlement frame
gas, for down-gassing vectors. `--save-raw <path>` writes the signed raw
transaction bytes, so mined transactions can be replayed as admission-level
rejection vectors and archived.

Nonce-race flags (see wallet/gen_nonce_race.py): `--note N` shields the note at
index N of a fixture's `shields` array (two notes into one tree). `--spend-key
KEY` drives the spend from fix[KEY] instead of fix[op], so the fixture's second
transfer `transfer_c` shares the harness. `--root-slot N` sets the recent-root
publication block directly (both race transfers bind the same root R, so they
share the block where the second shield completed the tree). Two transfers that
consume disjoint nullifier sets are both admissible from one shared sender at
nonce_seq 0 in either order: no sequential account nonce serializes them.
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
                   recent_root_refs=None, dry_run=False, sender_override=None,
                   max_fee_override=None, max_priority_override=None,
                   settle_gas_override=None, save_raw=None):
    signer = int.from_bytes(pk.public_key.to_canonical_address(), "big")
    sender = sender_override if sender_override is not None else signer
    chain_id = int(rpc(url, "eth_chainId", []), 16)
    signer_address = pk.public_key.to_checksum_address()
    nonce_address = "0x" + sender.to_bytes(20, "big").hex()
    nonce = int(rpc(url, "eth_getTransactionCount", [nonce_address, "latest"]), 16)
    blk = rpc(url, "eth_getBlockByNumber", ["latest", False])
    base_fee = int(blk.get("baseFeePerGas", "0x0"), 16)
    max_priority = max_priority_override if max_priority_override is not None else 10**9
    max_fee = max_fee_override if max_fee_override is not None else base_fee * 2 + max_priority
    if max_fee < base_fee or max_priority > max_fee:
        raise SystemExit("fee overrides require max_fee >= base_fee and max_priority <= max_fee")
    nonce_keys = protocol_nonces if protocol_nonces else [0]
    nonce_seq = 0 if protocol_nonces else nonce

    def build(sender_gas=10_000_000):
        if proof_verify:
            # The FAITHFUL shape, EIP-8141 [only_verify, pay] grammar (validated
            # live via OpenSponsor on 2026-07-05). Frame 0 self-verifies for the
            # EXECUTION scope only (0x02, target sender). Frame 1 is the pay
            # frame (0x01, PAYMENT scope) targeting the bounded paymaster. Frame
            # 0 verifies the proof; frame 1 authenticates that sender, binds the
            # same Spend bytes, and checks fee >= TXPARAM(max_cost) before
            # approving payment. The paymaster must be funded (it is the payer).
            paymaster, vcalldata = proof_verify
            frames = [
                Frame(mode=1, flags=0x02, target=sender, gas_limit=300_000, value=0, data=b""),
                Frame(mode=1, flags=0x01, target=paymaster, gas_limit=100_000, value=0, data=vcalldata),
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
            signatures=[FrameSig(FrameSig.SECP256K1, signer, b"", b"")],
            max_priority_fee=max_priority, max_fee=max_fee,
            recent_root_refs=recent_root_refs)
        s = pk.sign_msg_hash(tx.sig_hash())
        sig = bytes([s.v + 27]) + s.r.to_bytes(32, "big") + s.s.to_bytes(32, "big")
        tx.signatures = [FrameSig(FrameSig.SECP256K1, signer, b"", sig)]
        return tx

    tx = build() if settle_gas_override is None else build(sender_gas=settle_gas_override)
    raw = "0x" + tx.raw().hex()
    if save_raw:
        with open(save_raw, "w") as f:
            f.write(raw)

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
            print(f"           max_cost={tx.max_cost()}  total_gas_limit={tx.total_gas_limit()}")
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

    print(f"  frame tx: sender=0x{sender:040x} signer={signer_address} nonce_keys={nonce_keys} "
          f"raw_len={len(tx.raw())} max_cost={tx.max_cost()} sig_hash={tx.sig_hash().hex()[:18]}...")
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
    sender_override = None
    if "--sender" in sys.argv:
        i = sys.argv.index("--sender")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--sender requires an address")
        try:
            sender_override = int(sys.argv[i + 1], 16)
        except ValueError:
            raise SystemExit(f"invalid sender address: {sys.argv[i + 1]}") from None
        if sender_override == 0 or sender_override >= 1 << 160:
            raise SystemExit(f"invalid sender address: {sys.argv[i + 1]}")
    max_fee_override = None
    max_priority_override = None
    settle_gas_override = None
    save_raw = None
    nonce_keys_override = None
    note_index = None
    spend_key_override = None
    root_slot_override = None
    flip_proof = "--flip-proof" in sys.argv
    if "--note" in sys.argv:
        i = sys.argv.index("--note")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--note requires an index into fixture['shields']")
        note_index = int(sys.argv[i + 1], 0)
    if "--spend-key" in sys.argv:
        i = sys.argv.index("--spend-key")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--spend-key requires a fixture key (e.g. transfer_c)")
        spend_key_override = sys.argv[i + 1]
    if "--root-slot" in sys.argv:
        i = sys.argv.index("--root-slot")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--root-slot requires the block number that published the root")
        root_slot_override = int(sys.argv[i + 1], 0)
    if "--settle-gas" in sys.argv:
        i = sys.argv.index("--settle-gas")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--settle-gas requires a gas value")
        settle_gas_override = int(sys.argv[i + 1], 0)
    if "--save-raw" in sys.argv:
        i = sys.argv.index("--save-raw")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--save-raw requires a path")
        save_raw = sys.argv[i + 1]
    if "--nonce-keys" in sys.argv:
        i = sys.argv.index("--nonce-keys")
        if i + 1 >= len(sys.argv):
            raise SystemExit("--nonce-keys requires 0x..,0x..")
        nonce_keys_override = sorted(int(x, 16) for x in sys.argv[i + 1].split(","))
        if len(nonce_keys_override) != 2:
            raise SystemExit("--nonce-keys requires exactly two keys")
    for flag, target in (("--max-fee-per-gas", "max_fee"),
                         ("--max-priority-fee-per-gas", "max_priority")):
        if flag in sys.argv:
            i = sys.argv.index(flag)
            if i + 1 >= len(sys.argv):
                raise SystemExit(f"{flag} requires a wei value")
            try:
                value = int(sys.argv[i + 1], 0)
            except ValueError:
                raise SystemExit(f"invalid {flag} value: {sys.argv[i + 1]}") from None
            if value < 0:
                raise SystemExit(f"{flag} must be non-negative")
            if target == "max_fee":
                max_fee_override = value
            else:
                max_priority_override = value
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
        # The pool is the sender (frame-0 VERIFY identity and settle target in
        # one contract); --sender still overrides for adversarial vectors.
        if sender_override is None:
            sender_override = pool
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
        facts in the SENDER frame via EnvelopeProbe.

        `--spend-key KEY` reads the spend entry from fix[KEY] instead of
        fix[op_name] (the nonce-race fixture carries two transfers, `transfer`
        and `transfer_c`, against one shared root). `--root-slot N` overrides
        the recent-root publication block: both race transfers bind the SAME
        root R, so they share the block where the second shield completed the
        tree, rather than distinct cfg _slot_transfer/_slot_withdraw values."""
        fix_key = spend_key_override if spend_key_override is not None else op_name
        # Copy before adversarial mutation so the loaded fixture remains an
        # immutable source of truth for subsequent operations in this process.
        e = json.loads(json.dumps(fix[fix_key]))
        if flip_proof:
            e["proof"]["pA"][0] = hex(int(e["proof"]["pA"][0], 16) ^ 1)
        protocol_nonces = sorted([int(e["nf1"], 16), int(e["nf2"], 16)])  # strictly increasing
        verify = (paymaster_int,
                  cast_calldata(f"verifyProofOnly({SPEND_TUPLE})", spend_args(e)))
        slot = root_slot_override if root_slot_override is not None else cfg[f"_slot_{op_name}"]
        refs = [recent_root_ref(url, cfg, {"slot": slot, "root": e["root"]})]
        return e, protocol_nonces, verify, refs

    if op == "shield":
        if "shields" in fix:
            # nonce-race fixture: shield the note at --note N from the shields
            # array (both notes go into one tree; the second shield publishes
            # the shared root R the two race transfers reference).
            if note_index is None:
                raise SystemExit("this fixture has a 'shields' array; pass --note N (0-based)")
            s = fix["shields"][note_index]
            value, inner = int(s["value"]), s["inner"]
        else:
            value, inner = int(fix["shield_value"]), fix["inner_a"]
        calldata = cast_calldata("shield(bytes32)", inner)
        print(f"shield {value} wei via frame tx -> pool {cfg['pool']}")
        build_and_send(url, pk, pool, value, calldata, dry_run=dry)
    elif op == "transfer":
        e, protocol_nonces, verify, refs = spend_setup("transfer")
        if nonce_keys_override is not None:
            protocol_nonces = nonce_keys_override
        calldata = cast_calldata(f"transfer({SPEND_TUPLE},address)", spend_args(e), paymaster)
        print(f"join-split transfer via faithful frame tx (payer {paymaster}, proof verified on-chain)")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces, verify, refs,
                       dry_run=dry, sender_override=sender_override,
                       max_fee_override=max_fee_override, max_priority_override=max_priority_override,
                       settle_gas_override=settle_gas_override, save_raw=save_raw)
    elif op == "withdraw":
        e, protocol_nonces, verify, refs = spend_setup("withdraw")
        if nonce_keys_override is not None:
            protocol_nonces = nonce_keys_override
        calldata = cast_calldata(f"withdraw({SPEND_TUPLE},address,address)", spend_args(e),
                                 fix["recipient"], paymaster)
        print(f"join-split withdraw via faithful frame tx (payer {paymaster})")
        build_and_send(url, pk, pool, 0, calldata, protocol_nonces, verify, refs,
                       dry_run=dry, sender_override=sender_override,
                       max_fee_override=max_fee_override, max_priority_override=max_priority_override,
                       settle_gas_override=settle_gas_override, save_raw=save_raw)
    else:
        raise SystemExit(f"unknown op {op}")


if __name__ == "__main__":
    main()
