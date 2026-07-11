#!/usr/bin/env python3
"""Deploy bytecode for EnvelopeProbe, the stateless envelope reader the
settle-only ShieldedPool staticcalls (see EnvelopeProbe.yul). No constructor
args, no storage. Compiled from source on every invocation with the same
pinned solc as the paymaster.

Usage:
  probe.py --initcode   deploy initcode  -> cast send --create
  probe.py --runtime    expected deployed code -> cast code check
"""
import sys
from functools import lru_cache
from pathlib import Path
import subprocess

from paymaster import _solc


@lru_cache(maxsize=1)
def _compiled() -> tuple[bytes, bytes]:
    source = Path(__file__).with_name("EnvelopeProbe.yul")
    result = subprocess.run(
        [_solc(), "--strict-assembly", "--optimize", "--optimize-runs", "200", "--bin", source.name],
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


if __name__ == "__main__":
    init, runtime = _compiled()
    out = {"--initcode": init, "--runtime": runtime}[sys.argv[1]]
    print("0x" + out.hex())
