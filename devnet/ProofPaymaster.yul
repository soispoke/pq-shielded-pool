/// @title ProofPaymaster
/// @notice The proof-gated, spent-set-bound APPROVE paymaster for the EIP-8141
///         [only_verify, pay] faithful spend shape on the Hegotá devnet. It is
///         the pay VERIFY frame's target (flags 0x01, APPROVE_PAYMENT), and it
///         becomes the transaction's payer, so nothing is approved and no
///         nullifier is consumed unless the spend is fully valid.
///
/// In the pay frame it does three things, reverting (no APPROVE) on any failure:
///   1. SPENT-SET BINDING (the in-EVM form of ShieldedPool.checkKeySet, turning
///      the binding from trusted into proven). Requires len(nonce_keys) == 2
///      (TXPARAM 0x0D) and nonce_keys == sorted{nf1, nf2} (NONCEKEYLOAD 0xB9,
///      the ethrex extension for indexed nonce_keys[i]). EIP-8250 enforces
///      strictly-increasing keys at consensus, so k0 < k1; matching them to
///      {lo, hi} fixes the exact set AND rejects nf1 == nf2 (the same-note
///      attack) because k0 < k1 cannot satisfy lo == hi. This makes the two
///      proven nullifiers the transaction's protocol keyed-nonce set.
///   2. PROOF / ROOT / CANONICITY. STATICCALLs pool.verifySpend with its own
///      calldata (which is verifySpend(Spend)); verifySpend reverts on a bad
///      proof, a non-recent root, a non-canonical field element, or an
///      out-of-range amount.
///   3. APPROVE(scope = 1 = APPROVE_PAYMENT). Scope 0x1 does not require
///      frame_target == sender, so it composes with the execution-scope
///      self-verify frame ahead of it.
///
/// @dev NOT observer-friendly: it reads storage (the pool address) and makes an
///      external call (the STATICCALL), so the public-mempool ERC-7562 observer
///      rejects it and the spend submits builder-direct. A privacy spend needs
///      builder-direct anyway, since nonce_keys = [nf1, nf2] is not
///      public-mempool admissible (the public mempool admits only [0]). The
///      pay frame also busts today's MAX_VERIFY_GAS = 100k (verifySpend ~243k),
///      the one devnet-side item still pending.
///
///      APPROVE operand order matches OpenSponsor's compiled `60 01 5f 5f aa`.
///      Pay-frame calldata is verifySpend(Spend); Spend is a fully static
///      tuple, so after the 4-byte selector nf1 is at byte 68, nf2 at byte 100.
///      The pool address is a 32-byte constructor arg appended to the initcode
///      (as OpenSponsor takes its owner), read into storage slot 0 at deploy.
///
/// Scope bitmask (EIP-8141): 0x01 = APPROVE_PAYMENT, 0x02 = APPROVE_EXECUTION.
object "ProofPaymaster" {
    code {
        let argOffset := sub(codesize(), 32)
        codecopy(0, argOffset, 32)
        let pool := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
        if iszero(pool) { revert(0, 0) }
        sstore(0, pool)
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            // receive() — accept funding; the pay-frame target is the payer.
            if iszero(calldatasize()) { stop() }
            // need at least through nf2 (byte 100..131) of verifySpend(Spend)
            if lt(calldatasize(), 132) { revert(0, 0) }

            let nf1 := calldataload(68)
            let nf2 := calldataload(100)
            let lo := nf1
            let hi := nf2
            if gt(lo, hi) { lo := nf2  hi := nf1 }

            // 1. spent-set binding: nonce_keys == exactly {nf1, nf2}
            if iszero(eq(verbatim_1i_1o(hex"B0", 0x0D), 2)) { revert(0, 0) } // len(nonce_keys) == 2
            if iszero(eq(verbatim_1i_1o(hex"B9", 0), lo)) { revert(0, 0) }   // nonce_keys[0] == lo
            if iszero(eq(verbatim_1i_1o(hex"B9", 1), hi)) { revert(0, 0) }   // nonce_keys[1] == hi

            // 2. proof / root / canonicity, via the pool
            calldatacopy(0, 0, calldatasize())
            if iszero(staticcall(gas(), sload(0), 0, calldatasize(), 0, 0)) { revert(0, 0) }

            // 3. all bindings hold — approve payment
            verbatim_3i_0o(hex"AA", 0, 0, 1)
        }
    }
}
