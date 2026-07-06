#!/usr/bin/env python3
"""Deploy bytecode for ProofPaymaster, the proof-gated, spent-set-bound APPROVE
paymaster for the faithful spend shape. Source: ProofPaymaster.yul (this dir).

The pay VERIFY frame (flags 0x01, APPROVE_PAYMENT) targets this contract with
`verifySpend(Spend)` calldata. It:
  1. binds the envelope's nonce_keys to the proven nullifiers, the in-EVM form
     of ShieldedPool.checkKeySet: requires len(nonce_keys) == 2 (TXPARAM 0x0D)
     and nonce_keys == sorted{nf1, nf2} (NONCEKEYLOAD 0xB9). EIP-8250 enforces
     strictly-increasing keys, so matching {lo, hi} fixes the exact set and
     rejects nf1 == nf2 (the same-note attack). This turns the spent-set
     binding from trusted into proven.
  2. STATICCALLs pool.verifySpend (proof, recent root, canonicity).
  3. APPROVE(scope 0x1 = payment) only if both hold. The paymaster is the
     payer, so nothing is approved and no nullifier consumed unless the spend
     is fully valid.

Builder-direct, not public-mempool: it SLOADs the pool address and makes an
external call, both of which the ERC-7562 observer bans, and its pay frame
busts today's MAX_VERIFY_GAS = 100k (verifySpend ~243k). A privacy spend needs
builder-direct anyway, since nonce_keys = [nf1, nf2] is not public-mempool
admissible. See devnet/REVIEW.md.

The pool address is a 32-byte constructor arg appended to the initcode, read
into storage slot 0 at deploy (as OpenSponsor takes its owner). To regenerate
after editing ProofPaymaster.yul:
  solc --strict-assembly --bin ProofPaymaster.yul
and replace _INITCODE below (the trailing runtime is extracted automatically).

Usage:
  paymaster.py --initcode 0x<pool>   deploy initcode (append pool arg)  -> cast send --create
  paymaster.py --runtime  [0x<pool>] expected runtime (pool-independent) -> cast code check
"""
import sys

# solc 0.8.30 --strict-assembly --bin ProofPaymaster.yul (pool comes from the
# appended constructor arg, so this is independent of the pool address).
_INITCODE = bytes.fromhex(
    "602038036020815f3973ffffffffffffffffffffffffffffffffffffffff5f5116806028575f5ffd5b"
    "805f55606860375f3960685ff3fe36600557005b60843610156011575f5ffd5b60443560643581818082"
    "11156027578291508390505b6002600db0146034575f5ffd5b815fb914603f575f5ffd5b806001b914604b"
    "575f5ffd5b365f5f375f5f365f5f545afa605e575f5ffd5b60015f5faa50505050"
)
# The constructor returns the trailing runtime (PUSH1 len PUSH1 off ... RETURN).
_RUNTIME_LEN = 104
_RUNTIME = _INITCODE[-_RUNTIME_LEN:]


def initcode(pool: int) -> bytes:
    return _INITCODE + pool.to_bytes(32, "big")


def runtime(pool: int = 0) -> bytes:
    return _RUNTIME  # pool lives in storage, not the runtime code


if __name__ == "__main__":
    mode = sys.argv[1]
    pool = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    out = {"--initcode": initcode, "--runtime": runtime}[mode](pool)
    print("0x" + out.hex())
