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
///   2. PROOF / CANONICITY. STATICCALLs pool.verifyProofOnly with its own
///      calldata (which is verifyProofOnly(Spend)); it reverts on a bad proof, a
///      non-canonical field element, or an out-of-range amount. It does NOT read
///      the RecentRoots contract, so this frame reads no non-sender storage and
///      clears the ERC-7562 observer's non-sender-SLOAD ban. Root RECENCY is
///      enforced in the SENDER/exec frame (pool.verifySpend, via _spend): the
///      proof binds `root`, so a stale root reverts in execution, consuming only
///      the proven nullifiers, never a double-spend.
///   3. APPROVE(scope = 1 = APPROVE_PAYMENT). Scope 0x1 does not require
///      frame_target == sender, so it composes with the execution-scope
///      self-verify frame ahead of it.
///
/// @dev SLOAD-free. The pool address is a 32-byte constructor arg appended to
///      the initcode; the constructor appends it to the DEPLOYED code instead of
///      writing it to storage, and the runtime reads it back with CODECOPY from
///      its own last 32 bytes. Combined with verifyProofOnly (no RecentRoots
///      read), the pay frame touches no storage outside its own code, so it no
///      longer trips StorageReadNonSender. It still submits builder-direct: a
///      privacy spend needs that anyway, since nonce_keys = [nf1, nf2] is not
///      public-mempool admissible (the public mempool admits only [0]).
///
///      APPROVE operand order matches OpenSponsor's compiled `60 01 5f 5f aa`.
///      Pay-frame calldata is verifyProofOnly(Spend); Spend is a fully static
///      tuple, so after the 4-byte selector nf1 is at byte 68, nf2 at byte 100.
///
/// Scope bitmask (EIP-8141): 0x01 = APPROVE_PAYMENT, 0x02 = APPROVE_EXECUTION.
object "ProofPaymaster" {
    code {
        // read the 32-byte pool address appended to the initcode
        codecopy(0, sub(codesize(), 32), 32)
        let pool := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
        if iszero(pool) { revert(0, 0) }
        // deployed code = runtime || pool(32 bytes); no storage write
        let rsize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rsize)
        mstore(rsize, pool)
        return(0, add(rsize, 32))
    }
    object "runtime" {
        code {
            // receive() — accept funding; the pay-frame target is the payer.
            if iszero(calldatasize()) { stop() }
            // need at least through nf2 (byte 100..131) of verifyProofOnly(Spend)
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

            // 2. proof / canonicity, via the pool (no RecentRoots read).
            //    read the pool address from our own code (no SLOAD), then
            //    forward the pay-frame calldata verbatim.
            calldatacopy(0, 0, calldatasize())
            let ptr := calldatasize()
            codecopy(ptr, sub(codesize(), 32), 32)
            let pool := and(mload(ptr), 0xffffffffffffffffffffffffffffffffffffffff)
            // forward a large gas literal, not GAS(0x5a): the observer bans the
            // GAS opcode in validation frames. The EVM caps the request at 63/64
            // of remaining gas, so this forwards essentially all of it.
            if iszero(staticcall(0xffffffffffffffff, pool, 0, calldatasize(), 0, 0)) { revert(0, 0) }

            // 3. all bindings hold — approve payment
            verbatim_3i_0o(hex"AA", 0, 0, 1)
        }
    }
}
