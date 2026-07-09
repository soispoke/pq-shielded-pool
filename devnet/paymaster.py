#!/usr/bin/env python3
"""Deploy bytecode for ProofPaymaster, the proof-gated, spent-set-bound APPROVE
paymaster for the faithful spend shape. Source: ProofPaymaster.yul (this dir).

The pay VERIFY frame (flags 0x01, APPROVE_PAYMENT) targets this contract with
`verifyProofOnly(Spend)` calldata. It:
  1. binds the envelope's nonce_keys to the proven nullifiers, the in-EVM form
     of ShieldedPool.checkKeySet: requires len(nonce_keys) == 2 (TXPARAM 0x0D)
     and nonce_keys == sorted{nf1, nf2} (NONCEKEYLOAD 0xB9). EIP-8250 enforces
     strictly-increasing keys, so matching {lo, hi} fixes the exact set and
     rejects nf1 == nf2 (the same-note attack). This turns the spent-set
     binding from trusted into proven.
  2. STATICCALLs pool.verifyProofOnly (proof, canonicity). This does NOT read
     the RecentRoots contract, so the pay frame reads no non-sender storage.
     Root recency is enforced in the SENDER/exec frame (pool.verifySpend); the
     proof binds `root`, so a stale root reverts in execution and consumes only
     the proven nullifiers, never a double-spend.
  3. APPROVE(scope 0x1 = payment) only if both hold. The paymaster is the
     payer, so nothing is approved and no nullifier consumed unless the spend
     is fully valid.

SLOAD-free: the pool address is a 32-byte constructor arg appended to the
initcode; the constructor appends it to the DEPLOYED code (not storage) and the
runtime reads it back with CODECOPY. Combined with verifyProofOnly (no
RecentRoots read), the pay frame touches no storage outside its own code, so it
clears the ERC-7562 observer's StorageReadNonSender ban. It still submits
builder-direct: nonce_keys = [nf1, nf2] is not public-mempool admissible (the
public mempool admits only [0]). See devnet/REVIEW.md.

To regenerate after editing ProofPaymaster.yul:
  solc --strict-assembly --optimize --optimize-runs 200 --bin ProofPaymaster.yul
and replace _INITCODE below (the trailing runtime is extracted automatically).

Usage:
  paymaster.py --initcode 0x<pool>   deploy initcode (append pool arg)  -> cast send --create
  paymaster.py --runtime  0x<pool>   expected deployed code (runtime||pool) -> cast code check
"""
import sys

# solc 0.8.30 --strict-assembly --optimize --optimize-runs 200 --bin
# ProofPaymaster.yul. Creation code (constructor + embedded runtime); the pool
# address is the 32-byte arg appended by initcode(). SLOAD-free: the constructor
# appends the pool address to the deployed code and the runtime CODECOPYs it.
_INITCODE = bytes.fromhex(
    "602038601f19015f395f516001600160a01b0316801560295760209060729081602e5f398152015ff35b5f80fdfe"
    "36156070576084361060625760643560443580828082116066575b50506002600db0036062575fb90360625760"
    "01b903606257365f8037602038601f190136395f8036816001600160a01b038251166001600160401b03fa156062"
    "5760015f80aa005b5f80fd5b915091505f80601a565b00"
)
# The deployed code is runtime || pool(32 bytes); the runtime reads pool via
# CODECOPY of its own last 32 bytes, so runtime() is pool-dependent.
_RUNTIME_LEN = 114
_RUNTIME = _INITCODE[-_RUNTIME_LEN:]


def initcode(pool: int) -> bytes:
    return _INITCODE + pool.to_bytes(32, "big")


def runtime(pool: int = 0) -> bytes:
    return _RUNTIME + pool.to_bytes(32, "big")  # pool is appended to the code


if __name__ == "__main__":
    mode = sys.argv[1]
    pool = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0
    out = {"--initcode": initcode, "--runtime": runtime}[mode](pool)
    print("0x" + out.hex())
