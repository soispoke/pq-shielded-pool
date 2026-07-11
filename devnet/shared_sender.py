#!/usr/bin/env python3
"""Compile and parameterize the proof-authorized SharedPoolSender.yul.

Usage:
  shared_sender.py --initcode 0x<pool>  deploy initcode
  shared_sender.py --runtime  0x<pool>  expected deployed code
"""
import argparse
import subprocess
from functools import lru_cache
from pathlib import Path

from paymaster import address, solc_binary


@lru_cache(maxsize=1)
def _compiled() -> tuple[bytes, bytes]:
    source = Path(__file__).with_name("SharedPoolSender.yul")
    result = subprocess.run(
        [solc_binary(), "--strict-assembly", "--optimize", "--optimize-runs", "200", "--bin", source.name],
        cwd=source.parent, capture_output=True, text=True, check=True,
    )
    marker = "Binary representation:\n"
    if marker not in result.stdout:
        raise SystemExit(f"could not parse solc output: {result.stdout}\n{result.stderr}")
    init = bytes.fromhex(result.stdout.split(marker, 1)[1].splitlines()[0].strip())
    try:
        runtime = init.split(b"\xfe", 1)[1]
    except IndexError as exc:
        raise SystemExit("compiled Yul object has no constructor/runtime delimiter") from exc
    return init, runtime


def initcode(pool: int) -> bytes:
    init, _ = _compiled()
    return init + pool.to_bytes(32, "big")


def runtime(pool: int) -> bytes:
    _, deployed = _compiled()
    return deployed + pool.to_bytes(32, "big")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--initcode", dest="mode", action="store_const", const="--initcode")
    mode.add_argument("--runtime", dest="mode", action="store_const", const="--runtime")
    parser.add_argument("pool", type=address)
    args = parser.parse_args()
    pool = args.pool
    out = initcode(pool) if args.mode == "--initcode" else runtime(pool)
    print("0x" + out.hex())
