#!/usr/bin/env python3
"""Deploy bytecode for ProofPaymaster, the proof-authorized-sender and
max-cost-bound APPROVE paymaster for the faithful spend shape. Source:
ProofPaymaster.yul (this dir).

The pay VERIFY frame (flags 0x01, APPROVE_PAYMENT) targets this contract with
`verifyProofOnly(Spend)` calldata. It APPROVEs payment only if ALL hold:
  0. sender binding: TXPARAM(0x02) (authenticated tx.sender) == POOL_SENDER.
     This is the check that closes the paymaster drain. A spend proof is
     costless to mint only with fee=0; this paymaster requires fee>0. Because this pool also pins
     POOL_SENDER (ShieldedPool._spend reverts otherwise), binding sponsorship to
     that same pinned sender stops a third party from getting sponsored.
  1. spent-set binding: len(nonce_keys) == 2 (TXPARAM 0x0D), nonce_seq == 0
     (TXPARAM 0x01, EIP-8250 single-use), nonce_keys == sorted{nf1, nf2}
     (NONCEKEYLOAD 0xB9). Strictly-increasing keys fix the set and reject
     nf1 == nf2 (the same-note attack).
  1b. root binding: exactly one declared EIP-8272 recent-root reference
     (TXPARAM 0x0F), with source_id == keccak256(pad32(pool) || 0) (computed
     in-EVM) and root == the spend's proven root (RECENTROOTREFLOAD 0xB5).
     The protocol validates the reference's recency at admission and at block
     execution, so root recency is protocol-enforced, not pool storage.
  2. envelope binding: one signature, no blobs, and exactly three frames. The
     full [self-verify, pay, sender] grammar is checked, and the SENDER frame
     must target this pool with transfer(Spend,address) or
     withdraw(Spend,address,address). Its 544-byte Spend tuple must equal the
     tuple proven in the pay frame, and the fee recipient must equal this
     paymaster, so the payer cannot be charged for unrelated execution and is
     credited the proof-bound prepayment.
  3. sender authentication: frame 0 targets the immutable POOL_SENDER in
     VERIFY / execution-only mode. That contract verifies the exact proof,
     nonce keys, root reference and settlement data before APPROVE_EXECUTION.
     The paymaster does not repeat the Groth16 check; the pool still verifies
     independently during settlement.
  4. economic binding: the proof-bound fee covers TXPARAM(0x06), the same
     maximum transaction cost APPROVE_PAYMENT debits from this payer.

SLOAD-free: two 32-byte constructor args, pool || poolSender, are appended to the
initcode; the constructor appends them to the DEPLOYED code (not storage) and the
runtime reads them back with CODECOPY (pool at codesize-64, poolSender at
codesize-32).

The bytecode is compiled from ProofPaymaster.yul on every invocation with
pinned solc 0.8.30. There is no manually copied bytecode or runtime length.

Usage:
  paymaster.py --initcode 0x<pool> 0x<poolSender>   deploy initcode  -> cast send --create
  paymaster.py --runtime  0x<pool> 0x<poolSender>   expected deployed code -> cast code check
"""
import os
import argparse
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path

SOLC_VERSION = "0.8.30"


def solc_binary() -> str:
    candidates = [
        os.environ.get("SOLC"),
        shutil.which("solc"),
        str(Path.home() / "Library" / "Application Support" / "svm" /
            SOLC_VERSION / f"solc-{SOLC_VERSION}"),
        str(Path.home() / ".svm" / SOLC_VERSION / f"solc-{SOLC_VERSION}"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            version = subprocess.run([candidate, "--version"], capture_output=True, text=True,
                                     check=True).stdout
            if f"Version: {SOLC_VERSION}" not in version:
                raise SystemExit(f"expected solc {SOLC_VERSION}, got: {version.strip()}")
            return candidate
    raise SystemExit(f"solc {SOLC_VERSION} not found; set SOLC to the pinned binary")


@lru_cache(maxsize=1)
def _compiled() -> tuple[bytes, bytes]:
    source = Path(__file__).with_name("ProofPaymaster.yul")
    result = subprocess.run(
        [solc_binary(), "--strict-assembly", "--optimize", "--optimize-runs", "200", "--bin", source.name],
        cwd=source.parent, capture_output=True, text=True, check=True,
    )
    marker = "Binary representation:\n"
    if marker not in result.stdout:
        raise SystemExit(f"could not parse solc output: {result.stdout}\n{result.stderr}")
    init = bytes.fromhex(result.stdout.split(marker, 1)[1].splitlines()[0].strip())
    # solc's Yul object encoding separates constructor and embedded runtime
    # with INVALID (0xfe). ProofPaymaster's constructor contains no INVALID.
    try:
        runtime = init.split(b"\xfe", 1)[1]
    except IndexError as exc:
        raise SystemExit("compiled Yul object has no constructor/runtime delimiter") from exc
    return init, runtime


def initcode(pool: int, pool_sender: int) -> bytes:
    init, _ = _compiled()
    return init + pool.to_bytes(32, "big") + pool_sender.to_bytes(32, "big")


def runtime(pool: int = 0, pool_sender: int = 0) -> bytes:
    # pool||poolSender are appended to the code
    _, deployed = _compiled()
    return deployed + pool.to_bytes(32, "big") + pool_sender.to_bytes(32, "big")


def address(value: str) -> int:
    try:
        parsed = int(value, 16)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("expected a hexadecimal address") from exc
    if parsed <= 0 or parsed >= 1 << 160:
        raise argparse.ArgumentTypeError("address must be nonzero and exactly 20 bytes or less")
    return parsed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initcode", dest="mode", action="store_const", const="--initcode")
    mode.add_argument("--runtime", dest="mode", action="store_const", const="--runtime")
    parser.add_argument("pool", type=address)
    parser.add_argument("pool_sender", type=address)
    args = parser.parse_args()
    out = {"--initcode": initcode, "--runtime": runtime}[args.mode](args.pool, args.pool_sender)
    print("0x" + out.hex())
