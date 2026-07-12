#!/usr/bin/env python3
"""Compile and parameterize ShieldedPool.yul (the pool IS the sender).

The deployed runtime carries four appended immutables:
    poseidonT3 | poseidonT4 | verifier | probe   (four 32-byte words)

Usage:
  yul_pool.py --initcode 0x<t3> 0x<t4> 0x<verifier> 0x<probe>  deploy initcode
  yul_pool.py --artifact    write the bare initcode (no tail) to
                            build/shielded_pool_init.hex for the forge suite
                            (contracts/test/YulShieldedPool.t.sol). Rerun after
                            any ShieldedPool.yul change.

There is deliberately NO --runtime mode. The 0xfe-split used by probe.py /
paymaster.py / shared_sender.py to recover the runtime image from the init
binary is unsound for this object: the optimizer hoists the constructor's
32-byte zeroRoot constant into a DATA segment appended after the runtime
subobject, so everything-after-the-first-0xfe is the runtime plus trailing
data (and the init contains ten other incidental 0xfe bytes besides the
separator). Derive the expected deployed code by simulating the deployment
instead, which is exact under the node's own EVM:

  cast call --rpc-url <rpc> --create "$(yul_pool.py --initcode ...)"

run_live.sh verifies the deployed pool this way.
"""
import argparse
import subprocess
from functools import lru_cache
from pathlib import Path

from paymaster import address, solc_binary


@lru_cache(maxsize=1)
def _compiled() -> bytes:
    source = Path(__file__).with_name("ShieldedPool.yul")
    result = subprocess.run(
        [solc_binary(), "--strict-assembly", "--optimize", "--optimize-runs", "200", "--bin", source.name],
        cwd=source.parent, capture_output=True, text=True, check=True,
    )
    marker = "Binary representation:\n"
    if marker not in result.stdout:
        raise SystemExit(f"could not parse solc output: {result.stdout}\n{result.stderr}")
    return bytes.fromhex(result.stdout.split(marker, 1)[1].splitlines()[0].strip())


def _tail(t3: int, t4: int, verifier: int, probe: int) -> bytes:
    return b"".join(x.to_bytes(32, "big") for x in (t3, t4, verifier, probe))


def initcode(t3: int, t4: int, verifier: int, probe: int) -> bytes:
    return _compiled() + _tail(t3, t4, verifier, probe)


def write_artifact() -> Path:
    out = Path(__file__).with_name("build") / "shielded_pool_init.hex"
    out.parent.mkdir(exist_ok=True)
    out.write_text("0x" + _compiled().hex())  # no trailing newline: vm.parseBytes reads it whole
    return out


def main():
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--initcode", action="store_true")
    g.add_argument("--artifact", action="store_true")
    ap.add_argument("addrs", nargs="*", help="poseidonT3 poseidonT4 verifier probe")
    a = ap.parse_args()
    if a.artifact:
        print(write_artifact())
        return
    if len(a.addrs) != 4:
        ap.error("--initcode needs 4 addresses: poseidonT3 poseidonT4 verifier probe")
    t3, t4, ver, pr = (address(x) for x in a.addrs)
    print("0x" + initcode(t3, t4, ver, pr).hex())


if __name__ == "__main__":
    main()
