/// @title ProofPaymaster
/// @notice The proof-authorized-sender and max-cost-bound APPROVE paymaster for
///         the EIP-8141 [only_verify, pay] faithful spend shape on the Hegotá
///         devnet. It is the pay VERIFY frame's target (flags 0x01,
///         APPROVE_PAYMENT), and it becomes the transaction's payer, so nothing
///         is approved and no nullifier is consumed unless the spend is fully
///         valid AND submitted by the pool's pinned POOL_SENDER.
///
/// In the pay frame it does the following, reverting (no APPROVE) on any failure:
///   0. SENDER BINDING. TXPARAM(0x02) (tx.sender) MUST equal POOL_SENDER. This
///      closes the paymaster drain, but note WHY: a spend proof is costless to
///      mint (two zero-value dummy inputs conserve at 0, skip membership, and
///      expose two fresh distinct nullifiers), so "valid proof" is NOT evidence
///      of ownership. tx.sender is ALSO not authenticated on its own (ethrex
///      does no ECDSA recovery on it; it is a caller-chosen envelope field), so
///      this equality alone would not stop a forged sender. What authenticates
///      it is frame 0: the mandatory VERIFY(POOL_SENDER, execution-scope) frame
///      (checked in binding 2) runs the shared sender's proof authorization,
///      and a failing VERIFY frame marks the WHOLE transaction invalid with a
///      full rollback of the APPROVE debit. So the drain is closed by binding
///      0 AND the frame-0 VERIFY together; the frame-0 checks are load-bearing.
///      See devnet/REVIEW.md "Paymaster drain".
///   1. SPENT-SET BINDING (the in-EVM form of ShieldedPool.checkKeySet). Requires
///      len(nonce_keys) == 2 (TXPARAM 0x0D), nonce_seq == 0 (TXPARAM 0x01, the
///      EIP-8250 single-use requirement), and nonce_keys == sorted{nf1, nf2}
///      (NONCEKEYLOAD 0xB9, the ethrex extension for indexed nonce_keys[i]).
///      EIP-8250 enforces strictly-increasing keys at consensus, so k0 < k1;
///      matching them to {lo, hi} fixes the exact set AND rejects nf1 == nf2 (the
///      same-note attack) because k0 < k1 cannot satisfy lo == hi. This makes the
///      two proven nullifiers the transaction's protocol keyed-nonce set.
///   1b. ROOT BINDING (EIP-8272). Requires exactly one declared recent-root
///      reference (TXPARAM 0x0F) whose source_id is the pool's
///      (keccak256(pad32(pool) || SALT), SALT = 0, computed in-EVM from the
///      pool address) and whose root equals the spend's proven root
///      (RECENTROOTREFLOAD 0xB5, fields 0 and 2). The protocol has already
///      validated the reference against committed state and the recency
///      window, at admission and again at block execution, so this match
///      makes root recency protocol-enforced. The reference's slot field is
///      left free: recency is the protocol's window check, not a fixed slot.
///   2. ENVELOPE BINDING. Requires one signature, no blobs, and exactly three
///      frames. It checks the full [self-verify, pay, sender] grammar, including
///      each frame's target, mode, flags, gas limit, value, and data length. The SENDER
///      frame must target this pool and call transfer(Spend,address) or
///      withdraw(Spend,address,address), with the 544-byte Spend tuple
///      byte-for-byte equal to the tuple proven in this pay frame. The final
///      feeRecipient argument MUST equal this paymaster, so shielded fee value
///      is credited to the actual payer. No unrelated or appended execution
///      can be charged to it.
///   3. SENDER AUTHENTICATION. Frame 0 targets the immutable POOL_SENDER in
///      VERIFY / execution-only mode. The transaction is valid only if that
///      proof-authorized contract checked the exact proof, key set, root, and
///      settlement calldata and called APPROVE_EXECUTION. The paymaster does
///      not repeat its Groth16 check, keeping the validation prefix below the
///      devnet's 500k budget. In the preferred immutable dispatcher deployment,
///      this frame-0 check is the sole proof verification; settlement rebinds
///      the authenticated envelope but does not repeat the Groth16 pairing.
///   4. ECONOMIC BINDING. The proof-bound fee MUST cover TXPARAM(0x06), the
///      exact maximum cost APPROVE_PAYMENT debits and later refunds down to
///      actual cost. This prevents an open submitter choosing gas parameters
///      whose maximum liability exceeds the paymaster's compensation.
///   5. APPROVE(scope = 1 = APPROVE_PAYMENT). Scope 0x1 does not require
///      frame_target == sender, so it composes with the execution-scope
///      self-verify frame ahead of it.
///
/// @dev Fee routing. The SENDER calldata names this paymaster as feeRecipient,
///      and the pool records a pull credit for that exact address. Anyone may
///      later push the credit to the paymaster itself, replenishing its gas
///      float without giving the caller any redirect authority.
///
/// @dev SLOAD-free. Two 32-byte constructor args, pool || poolSender, are
///      appended to the initcode; the constructor appends them to the DEPLOYED
///      code instead of storage, and the runtime reads them back with CODECOPY
///      from its own last 64 bytes (pool at codesize-64, poolSender at
///      codesize-32). The pay frame touches no storage, so it does not trip
///      StorageReadNonSender.
///
///      APPROVE operand order matches OpenSponsor's compiled `60 01 5f 5f aa`.
///      Pay-frame calldata is verifyProofOnly(Spend); Spend is a fully static
///      tuple (slot retired with the pool's RecentRoots emulation), so after
///      the 4-byte selector root is at byte 4, nf1 at 68, nf2 at 100.
///
/// Scope bitmask (EIP-8141): 0x01 = APPROVE_PAYMENT, 0x02 = APPROVE_EXECUTION.
object "ProofPaymaster" {
    code {
        // initcode tail = pool(32) || poolSender(32); read both, then append
        // them to the deployed code (no storage write).
        codecopy(0, sub(codesize(), 64), 64)
        let pool := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
        let poolSender := and(mload(32), 0xffffffffffffffffffffffffffffffffffffffff)
        if iszero(pool) { revert(0, 0) }
        if iszero(poolSender) { revert(0, 0) }
        // deployed code = runtime || pool(32) || poolSender(32)
        let rsize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rsize)
        mstore(rsize, pool)
        mstore(add(rsize, 32), poolSender)
        return(0, add(rsize, 64))
    }
    object "runtime" {
        code {
            function txParam(param) -> value {
                value := verbatim_1i_1o(hex"B0", param)
            }
            // FRAMEPARAM pops frameIndex first (stack top), then param.
            function frameParam(frameIndex, param) -> value {
                value := verbatim_2i_1o(hex"B3", frameIndex, param)
            }
            // FRAMEDATALOAD pops offset first (stack top), then frameIndex.
            function frameDataLoad(frameIndex, offset) -> value {
                value := verbatim_2i_1o(hex"B1", offset, frameIndex)
            }
            // RECENTROOTREFLOAD (0xB5) pops field first (stack top), then index.
            // field: 0 = source_id, 1 = slot, 2 = root.
            function recentRootRef(field, index) -> value {
                value := verbatim_2i_1o(hex"B5", field, index)
            }

            // receive() — accept funding; the pay-frame target is the payer.
            if iszero(calldatasize()) { stop() }
            // Bind the pay-frame data carrier to exactly the canonical
            // verifyProofOnly(Spend) encoding: selector 0x8cc8fe8d and the full
            // static 548 bytes. Frame 2's Spend tuple is byte-equal below, and
            // the proof-authorized sender verified that exact tuple in frame 0.
            if iszero(eq(calldatasize(), 548)) { revert(0, 0) }
            if iszero(eq(shr(224, calldataload(0)), 0x8cc8fe8d)) { revert(0, 0) }

            // Load immutable configuration from the last 64 code bytes.
            codecopy(0, sub(codesize(), 64), 64)
            let pool := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
            let poolSender := and(mload(32), 0xffffffffffffffffffffffffffffffffffffffff)

            // 0. sender binding: only POOL_SENDER may be
            //    sponsored. TXPARAM(0x02) is the authenticated tx.sender. This is
            //    the check that closes the drain (a valid proof is costless to
            //    mint from dummy inputs, so it is not authorization on its own).
            if iszero(eq(txParam(0x02), poolSender)) { revert(0, 0) }

            let nf1 := calldataload(68)
            let nf2 := calldataload(100)
            // The fee is proof-bound (and frame 2 is byte-equal below). It must
            // cover the same maximum cost APPROVE_PAYMENT will debit.
            let fee := calldataload(228)
            if lt(fee, txParam(0x06)) { revert(0, 0) }
            let lo := nf1
            let hi := nf2
            if gt(lo, hi) { lo := nf2  hi := nf1 }

            // 1. spent-set binding: nonce_keys == exactly {nf1, nf2}, seq 0.
            if iszero(eq(txParam(0x0D), 2)) { revert(0, 0) } // len(nonce_keys) == 2
            if iszero(iszero(txParam(0x01))) { revert(0, 0) } // nonce_seq == 0
            if iszero(eq(verbatim_1i_1o(hex"B9", 0), lo)) { revert(0, 0) }   // nonce_keys[0] == lo
            if iszero(eq(verbatim_1i_1o(hex"B9", 1), hi)) { revert(0, 0) }   // nonce_keys[1] == hi

            // 1b. root binding: exactly one declared EIP-8272 reference, under
            //     the pool's source_id (keccak256(pad32(pool) || SALT), SALT = 0,
            //     ethrex's native-write derivation), carrying the spend's proven
            //     root (calldata offset 4). The protocol validated the reference
            //     (committed entry, recency window) at admission and re-validates
            //     at block execution, so this match makes root recency
            //     protocol-enforced. Slot is left free: recency IS the window.
            if iszero(eq(txParam(0x0F), 1)) { revert(0, 0) }
            mstore(0, pool)
            mstore(32, 0)
            if iszero(eq(recentRootRef(0, 0), keccak256(0, 64))) { revert(0, 0) }
            if iszero(eq(recentRootRef(2, 0), calldataload(4))) { revert(0, 0) }

            // 2. exact envelope grammar: one signature, no blobs, and exactly
            //    [self-verify(poolSender), pay(this), SENDER(pool)].
            if iszero(eq(txParam(0x09), 3)) { revert(0, 0) }
            if iszero(eq(txParam(0x0A), 1)) { revert(0, 0) } // this is frame 1
            if iszero(eq(txParam(0x0B), 1)) { revert(0, 0) }
            if txParam(0x07) { revert(0, 0) }

            // frame 0: proof-authorized shared sender, execution only.
            if iszero(eq(frameParam(0, 0x00), poolSender)) { revert(0, 0) }
            if iszero(eq(frameParam(0, 0x02), 1)) { revert(0, 0) } // VERIFY
            if iszero(eq(frameParam(0, 0x03), 2)) { revert(0, 0) } // execution
            if frameParam(0, 0x04) { revert(0, 0) } // empty data
            if iszero(eq(frameParam(0, 0x01), 300000)) { revert(0, 0) }
            if frameParam(0, 0x08) { revert(0, 0) } // zero value

            // frame 1: this paymaster, payment approval only, with this calldata.
            if iszero(eq(frameParam(1, 0x00), address())) { revert(0, 0) }
            if iszero(eq(frameParam(1, 0x02), 1)) { revert(0, 0) } // VERIFY
            if iszero(eq(frameParam(1, 0x03), 1)) { revert(0, 0) } // payment
            if iszero(eq(frameParam(1, 0x04), 548)) { revert(0, 0) }
            if iszero(eq(frameParam(1, 0x01), 100000)) { revert(0, 0) }
            if frameParam(1, 0x08) { revert(0, 0) }

            // frame 2: the only paid execution. It must call this pool with the
            // same Spend tuple and credit the proof-bound fee to this paymaster.
            if iszero(eq(frameParam(2, 0x00), pool)) { revert(0, 0) }
            if iszero(eq(frameParam(2, 0x02), 2)) { revert(0, 0) } // SENDER
            if frameParam(2, 0x03) { revert(0, 0) }
            if iszero(eq(frameParam(2, 0x01), 10000000)) { revert(0, 0) }
            if frameParam(2, 0x08) { revert(0, 0) }
            let senderDataLen := frameParam(2, 0x04)
            let senderSelector := shr(224, frameDataLoad(2, 0))
            switch senderDataLen
            case 580 {
                if iszero(eq(senderSelector, 0x751a8fc5)) { revert(0, 0) } // transfer(Spend,address)
                if iszero(eq(frameDataLoad(2, 548), address())) { revert(0, 0) }
            }
            case 612 {
                if iszero(eq(senderSelector, 0x215ae4c7)) { revert(0, 0) } // withdraw(Spend,address,address)
                if iszero(eq(frameDataLoad(2, 580), address())) { revert(0, 0) }
            }
            default { revert(0, 0) }
            for { let offset := 4 } lt(offset, 548) { offset := add(offset, 32) } {
                if iszero(eq(frameDataLoad(2, offset), calldataload(offset))) { revert(0, 0) }
            }

            // 3-4. Frame 0 is the proof-authorized sender; fee covers max cost.
            // 5. All bindings hold — approve payment.
            verbatim_3i_0o(hex"AA", 0, 0, 1)
        }
    }
}
