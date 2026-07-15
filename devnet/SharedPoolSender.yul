/// @title SharedPoolSender
/// @notice Proof-authorized execution identity for the shielded pool. Every
///         spend uses this contract as tx.sender, so EIP-8250 nullifier keys
///         share one sender namespace without an operator-held key.
///
///         This contract authenticates the exact transaction grammar, proof,
///         nonce-key set, and recent-root reference before approving execution.
///         The pool verifies the proof again during settlement as the
///         independent noteholder-safety boundary. The paymaster authenticates
///         this frame and therefore does not perform a third proof check.
///         It approves execution only when all of the following hold:
///
///           - this is frame 0 of exactly three frames;
///           - tx.sender and frame-0 target are this contract;
///           - frame 0 is VERIFY / execution-only, empty and zero-value;
///           - frame 1 is VERIFY / payment-only and zero-value;
///           - frame 2 is SENDER, directly targets the configured pool,
///             carries zero value, has the fixed safe settlement gas limit,
///             and calls the exact transfer/withdraw ABI;
///           - two keyed nonces at seq 0, one recent-root reference, one outer
///             signature, and no blobs are present.
///
///         The configured pool is appended to deployed code, never storage,
///         and pool.verifyProofOnly is calldata-only, so validation is SLOAD-free.
object "SharedPoolSender" {
    code {
        // initcode tail = pool(32); append it to the deployed runtime.
        codecopy(0, sub(codesize(), 32), 32)
        let pool := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)
        if iszero(pool) { revert(0, 0) }
        let rsize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rsize)
        mstore(rsize, pool)
        return(0, add(rsize, 32))
    }
    object "runtime" {
        code {
            function txParam(param) -> value {
                value := verbatim_1i_1o(hex"B0", param)
            }
            function frameParam(frameIndex, param) -> value {
                value := verbatim_2i_1o(hex"B3", frameIndex, param)
            }
            function frameDataLoad(frameIndex, offset) -> value {
                value := verbatim_2i_1o(hex"B1", offset, frameIndex)
            }
            function recentRootRef(field, index) -> value {
                value := verbatim_2i_1o(hex"B5", field, index)
            }

            codecopy(0, sub(codesize(), 32), 32)
            let pool := and(mload(0), 0xffffffffffffffffffffffffffffffffffffffff)

            // Envelope: this contract is the shared sender and is currently
            // executing the only execution-approval frame.
            if iszero(eq(txParam(0x02), address())) { revert(0, 0) }
            if iszero(eq(txParam(0x09), 3)) { revert(0, 0) }
            if txParam(0x0A) { revert(0, 0) }
            if iszero(eq(txParam(0x0B), 1)) { revert(0, 0) }
            if txParam(0x07) { revert(0, 0) }
            if iszero(eq(txParam(0x0D), 2)) { revert(0, 0) }
            if txParam(0x01) { revert(0, 0) }
            if iszero(eq(txParam(0x0F), 1)) { revert(0, 0) }

            // Frame 0: VERIFY(this), execution approval only.
            if iszero(eq(frameParam(0, 0x00), address())) { revert(0, 0) }
            if iszero(eq(frameParam(0, 0x02), 1)) { revert(0, 0) }
            if iszero(eq(frameParam(0, 0x03), 2)) { revert(0, 0) }
            if frameParam(0, 0x04) { revert(0, 0) }
            if iszero(eq(frameParam(0, 0x01), 300000)) { revert(0, 0) }
            if frameParam(0, 0x08) { revert(0, 0) }

            // Frame 1: a payment-only VERIFY frame. The selected paymaster
            // authenticates this sender, binds settlement and caps liability.
            if iszero(eq(frameParam(1, 0x02), 1)) { revert(0, 0) }
            if iszero(eq(frameParam(1, 0x03), 1)) { revert(0, 0) }
            if iszero(eq(frameParam(1, 0x01), 100000)) { revert(0, 0) }
            if frameParam(1, 0x08) { revert(0, 0) }

            // Frame 2: the only execution, directly into the configured pool.
            if iszero(eq(frameParam(2, 0x00), pool)) { revert(0, 0) }
            if iszero(eq(frameParam(2, 0x02), 2)) { revert(0, 0) }
            if frameParam(2, 0x03) { revert(0, 0) }
            // Exact, deliberately generous settlement gas prevents a copied
            // valid spend being re-wrapped to OOG after nullifier consumption.
            if iszero(eq(frameParam(2, 0x01), 10000000)) { revert(0, 0) }
            if frameParam(2, 0x08) { revert(0, 0) }
            let dataLen := frameParam(2, 0x04)
            let selector := shr(224, frameDataLoad(2, 0))
            switch dataLen
            case 548 {
                if iszero(eq(selector, 0xb9947fa0)) { revert(0, 0) }
                // transfer: publicAmount == 0 and ctx == 0.
                if frameDataLoad(2, 196) { revert(0, 0) }
                if frameDataLoad(2, 260) { revert(0, 0) }
            }
            case 580 {
                if iszero(eq(selector, 0xd677b46e)) { revert(0, 0) }
                // withdraw: positive public amount and ctx names the canonical
                // recipient exactly, so settlement cannot fail after approval.
                if iszero(frameDataLoad(2, 196)) { revert(0, 0) }
                let recipient := frameDataLoad(2, 548)
                if or(iszero(recipient), shr(160, recipient)) { revert(0, 0) }
                if iszero(eq(frameDataLoad(2, 260), recipient)) { revert(0, 0) }
            }
            default { revert(0, 0) }

            // The protocol nonce set is exactly the proof's two nullifiers.
            let nf1 := frameDataLoad(2, 68)
            let nf2 := frameDataLoad(2, 100)
            let lo := nf1
            let hi := nf2
            if gt(lo, hi) { lo := nf2  hi := nf1 }
            if iszero(eq(verbatim_1i_1o(hex"B9", 0), lo)) { revert(0, 0) }
            if iszero(eq(verbatim_1i_1o(hex"B9", 1), hi)) { revert(0, 0) }

            // The declared protocol-validated reference names this pool's
            // source and the exact root carried by the proof.
            mstore(0, pool)
            mstore(32, 0)
            if iszero(eq(recentRootRef(0, 0), keccak256(0, 64))) { revert(0, 0) }
            if iszero(eq(recentRootRef(2, 0), frameDataLoad(2, 4))) { revert(0, 0) }

            // Build verifyProofOnly(Spend) from frame 2 in memory. Spend is a
            // static 544-byte tuple at offsets [4, 548); its selector is fixed.
            mstore(0, shl(224, 0x8cc8fe8d))
            for { let offset := 4 } lt(offset, 548) { offset := add(offset, 32) } {
                mstore(offset, frameDataLoad(2, offset))
            }
            // Fixed literal, not GAS: validation observers ban the GAS opcode.
            if iszero(staticcall(500000, pool, 0, 548, 0, 0)) { revert(0, 0) }

            // APPROVE_EXECUTION. Scope 0x2 also requires frame target ==
            // tx.sender at the protocol handler, repeating the identity bind.
            verbatim_3i_0o(hex"AA", 0, 0, 2)
        }
    }
}
