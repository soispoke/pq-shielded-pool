/// @title SharedPoolSender
/// @notice TEST-ONLY contract-sender capability probe for the shielded pool.
///         Every spend uses this contract as tx.sender, so EIP-8250 nullifier
///         keys share one sender namespace without an operator-held key.
///
///         DO NOT use this stage with real notes. It authenticates the frame
///         grammar but deliberately delegates proof/key/root validity to the
///         paymaster and pool. A malicious self-funded payment approver could
///         therefore consume a revealed victim nullifier and let settlement
///         revert. The production successor MUST verify the exact proof,
///         nonce-key set and recent-root reference before APPROVE_EXECUTION.
///
///         This capability stage authenticates the exact transaction
///         grammar and delegates spend validity to the proof paymaster and the
///         pool, both of which independently verify the proof and envelope.
///         It approves execution only when all of the following hold:
///
///           - this is frame 0 of exactly three frames;
///           - tx.sender and frame-0 target are this contract;
///           - frame 0 is VERIFY / execution-only, empty and zero-value;
///           - frame 1 is VERIFY / payment-only and zero-value;
///           - frame 2 is SENDER, directly targets the configured pool,
///             carries zero value, and calls the exact transfer/withdraw ABI;
///           - two keyed nonces at seq 0, one recent-root reference, one outer
///             signature, and no blobs are present.
///
///         The configured pool is appended to deployed code, never storage,
///         so validation remains SLOAD-free. The safe next stage must bind the
///         full spend tuple here before this can replace the pinned operator.
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
            if frameParam(0, 0x08) { revert(0, 0) }

            // Frame 1: a payment-only VERIFY frame. The selected paymaster is
            // responsible for its own proof, key, root and calldata checks.
            if iszero(eq(frameParam(1, 0x02), 1)) { revert(0, 0) }
            if iszero(eq(frameParam(1, 0x03), 1)) { revert(0, 0) }
            if frameParam(1, 0x08) { revert(0, 0) }

            // Frame 2: the only execution, directly into the configured pool.
            if iszero(eq(frameParam(2, 0x00), pool)) { revert(0, 0) }
            if iszero(eq(frameParam(2, 0x02), 2)) { revert(0, 0) }
            if frameParam(2, 0x03) { revert(0, 0) }
            if frameParam(2, 0x08) { revert(0, 0) }
            let dataLen := frameParam(2, 0x04)
            let selector := shr(224, frameDataLoad(2, 0))
            switch dataLen
            case 580 {
                if iszero(eq(selector, 0x751a8fc5)) { revert(0, 0) }
            }
            case 612 {
                if iszero(eq(selector, 0x215ae4c7)) { revert(0, 0) }
            }
            default { revert(0, 0) }

            // APPROVE_EXECUTION. Scope 0x2 also requires frame target ==
            // tx.sender at the protocol handler, repeating the identity bind.
            verbatim_3i_0o(hex"AA", 0, 0, 2)
        }
    }
}
