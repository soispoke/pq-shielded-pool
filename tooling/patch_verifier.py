#!/usr/bin/env python3
"""Make snarkjs's generated verifier legal in the restricted VERIFY prefix.

The Hegotá validation observer bans the GAS opcode. snarkjs emits
`staticcall(sub(gas(), 2000), ...)` for ECADD, ECMUL, and pairing. Replace all
three with a fixed request; EIP-150 still caps it to 63/64 of remaining gas.
Fail closed if a future snarkjs output changes shape.
"""
from pathlib import Path

VERIFIER = Path(__file__).parent.parent / "contracts" / "src" / "Groth16Verifier.sol"
NEEDLE = "staticcall(sub(gas(), 2000),"
REPLACEMENT = "staticcall(500000,"
LEGACY_REPLACEMENT = "staticcall(30000000,"


def main():
    source = VERIFIER.read_text()
    if source.count(LEGACY_REPLACEMENT) == 3:
        source = source.replace(LEGACY_REPLACEMENT, REPLACEMENT)
        VERIFIER.write_text(source)
        print("tightened 3 legacy verifier gas requests to 500000")
        return
    count = source.count(NEEDLE)
    if count == 0 and source.count(REPLACEMENT) == 3:
        print("verifier already uses 3 fixed-gas precompile calls")
        return
    if count != 3:
        raise SystemExit(f"expected 3 snarkjs GAS calls, found {count}; inspect generated verifier")
    VERIFIER.write_text(source.replace(NEEDLE, REPLACEMENT))
    print("patched 3 verifier precompile calls to fixed gas")


if __name__ == "__main__":
    main()
