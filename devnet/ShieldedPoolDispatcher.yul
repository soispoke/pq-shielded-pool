/// @title ShieldedPoolDispatcher (Yul)
/// @notice The production-preferred pool-as-sender shell: a thin immutable Yul
///         object deployed AT the pool address. It does only what must be Yul,
///         and DELEGATECALLs everything else to a reviewable Solidity settlement
///         implementation (contracts/src/ShieldedPoolLogic.sol).
///         The delegated pool is native-ETH only; this shell contains no ERC-20
///         or token-conversion path.
///
///         Two entrypoints:
///           - empty calldata: the frame-0 VERIFY frame. This
///             is the sole reason the pool must be Yul: it reads the frame-tx
///             envelope opcodes (TXPARAM / FRAMEPARAM / FRAMEDATALOAD /
///             NONCEKEYLOAD / RECENTROOTREFLOAD), authenticates the grammar,
///             the exact keyed-nonce set, and the recent-root reference,
///             verifies the proof over the byte-exact final-frame Spend, and
///             emits combined execution-and-payment approval in the canonical
///             self-paying shape. The optional sponsored shape uses execution
///             approval here and payment approval in a separate VERIFY frame.
///           - any nonzero calldata: forwarded by DELEGATECALL to the
///             implementation, so shield / transfer / withdraw / verifyProofOnly
///             / claims / views all run as compiled, memory-safe Solidity in
///             the pool's storage, address, and value context.
///
///         This replaces the 600-line monolithic ShieldedPool.yul: the
///         fund-holding hand-audited surface shrinks to this file, and the
///         settlement equivalence oracle collapses to one (the Solidity
///         implementation IS the settlement, no separate Yul reimplementation
///         to keep in differential sync).
///
///         Storage lives at this dispatcher (the pool). The dispatcher writes
///         storage only in its constructor (currentRoot at slot 22, matching
///         the implementation's layout) and never again; every later state
///         change is the implementation's, executed here under DELEGATECALL.
///
///         The single proof verification is INLINE in verifyFrameApprove
///         (frame 0), with a direct STATICCALL to the immutable Groth16
///         verifier. It is not delegated to the implementation: ethrex's
///         validation observer bans DELEGATECALL inside a VERIFY frame (the
///         delegate target's code could vary, breaking validation
///         determinism), so a delegatecall-to-logic proof check simulates fine
///         but the builder silently skips the transaction. A plain STATICCALL
///         to the verifier is observer-legal (the monolith and SharedPoolSender
///         used exactly this live). So the dispatcher carries the two
///         validation-frame concerns that MUST run at the sender address in
///         Yul, frame parsing and proof verification, and the implementation
///         carries settlement; that is the seam. Its soundness (execution
///         approval can only come from this immutable dispatcher's own code, so
///         the settlement proof re-check is redundant) is the narrow argument
///         in devnet/REVIEW.md, and it depends on THIS dispatcher's frame-0
///         code and its verifier binding being immutable: both the
///         implementation and verifier addresses are baked into the deployed
///         code tail, never stored, never upgradeable.
///
///         Deploy: initcode tail = implementation address || verifier address
///         (two 32-byte words), appended to the deployed runtime.
object "ShieldedPoolDispatcher" {
    code {
        // ---- constructor ----
        // Seed the pool's currentRoot (slot 22) to the empty-tree root and
        // publish it once, exactly as the monolith / ShieldedPool.sol did, then
        // return runtime || implementation-address tail.
        let zeroRoot := 0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e
        sstore(22, zeroRoot)
        mstore(0, 0) // SALT
        mstore(32, zeroRoot)
        if iszero(call(gas(), 0x8272, 0, 0, 64, 0, 0)) {
            mstore(0, shl(224, 0x5c3c03e8)) // RootPublishFailed()
            revert(0, 4)
        }
        let rsize := datasize("runtime")
        // move the 64-byte tail (implementation || verifier) to sit right after
        // the runtime image, then lay the runtime image at 0 and return both.
        codecopy(rsize, sub(codesize(), 64), 64)
        datacopy(0, dataoffset("runtime"), rsize)
        return(0, add(rsize, 64))
    }

    object "runtime" {
        code {
            // ================= envelope opcodes (EIP-8141/8250/8272) =========
            function txParam(param) -> value { value := verbatim_1i_1o(hex"B0", param) }
            function frameParam(frameIndex, param) -> value { value := verbatim_2i_1o(hex"B3", frameIndex, param) }
            function frameDataLoad(frameIndex, offset) -> value { value := verbatim_2i_1o(hex"B1", offset, frameIndex) }
            function nonceKey(i) -> value { value := verbatim_1i_1o(hex"B9", i) }
            function recentRootRef(field, index) -> value { value := verbatim_2i_1o(hex"B5", field, index) }
            function approveExecution() { verbatim_3i_0o(hex"AA", 0, 0, 2) }
            function approveExecutionAndPayment() { verbatim_3i_0o(hex"AA", 0, 0, 3) }

            // ================= named errors (ShieldedPool.sol selectors) =====
            // The frame-0 path reuses the pool's error selectors so a
            // validation-prefix simulation failure is attributable from the RPC
            // error alone; the same selectors the implementation reverts with.
            function fail(sel) {
                mstore(0x00, shl(224, sel))
                revert(0x00, 0x04)
            }
            function errNotFaithfulShape() -> s { s := 0xe6d22e28 }
            function errRootNotBound() -> s { s := 0xaf501e1c } // RootNotBoundToReference()
            function errProofInvalid() -> s { s := 0x7fcdd1f4 }
            function errKeySetMismatch() -> s { s := 0x586e51ed }
            function errTransferShape() -> s { s := 0xef7a30fa }
            function errWithdrawShape() -> s { s := 0x7f54f5ab }
            function errCtxRecipient() -> s { s := 0x49cb8b3a } // CtxDoesNotNameRecipient()
            function errNotCanonical() -> s { s := 0xd7c7beeb }
            function errValueTooLarge() -> s { s := 0x2ad907fb }
            function errFeeBelowMaxCost() -> s { s := 0x315cb54e }
            function errInvalidDomain() -> s { s := 0xeb127982 }
            function errZeroNullifier() -> s { s := 0xcbbbbfe1 }

            // ================= constants (proof verification) ================
            function fieldP() -> v { v := 21888242871839275222246405745257275088548364400416034343698204186575808495617 }
            function maxValue() -> v { v := 0x100000000000000000000000000000000 } // 1 << 128
            function domainTag() -> v { v := 0x40752e102d2a749c61d42a71e297edd3b493de639003b9480a700d589d98065b }

            // sourceId() == keccak256(pad32(this) || SALT); address(this) is the
            // pool (dispatcher) in every context this runs.
            function sourceId() -> id {
                mstore(0x00, address())
                mstore(0x20, 0)
                id := keccak256(0x00, 0x40)
            }

            // domain == keccak256(DOMAIN_TAG || chainId || sourceId) % P. Read
            // sourceId into a local first (it uses scratch 0x00..0x40).
            function domainVal() -> d {
                let src := sourceId()
                mstore(0x00, domainTag())
                mstore(0x20, chainid())
                mstore(0x40, src)
                d := mod(keccak256(0x00, 0x60), fieldP())
            }

            // Tail immutables: implementation at codesize-64, verifier at -32.
            function impl() -> a {
                codecopy(0x00, sub(codesize(), 64), 32)
                a := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }
            function verifierAddr() -> a {
                codecopy(0x00, sub(codesize(), 32), 32)
                a := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }

            // Verify the proof INLINE from the settle frame's Spend tuple (offsets
            // relative to the SENDER calldata: 4-byte selector, then the static
            // 544-byte tuple). Canonicity + range + domain, then a direct
            // STATICCALL to the immutable verifier (no delegatecall: the
            // validation observer bans it in a VERIFY frame). Mirrors
            // ShieldedPoolLogic.verifyProofOnly + _verifyProof over the same
            // nine public signals, so frame-0 authenticates the exact tuple the
            // SENDER frame will settle. Fixed 500k gas literal, no GAS opcode.
            function verifyFrameProof(settleIndex) {
                let root := frameDataLoad(settleIndex, 4)
                let dom := frameDataLoad(settleIndex, 36)
                let nf1 := frameDataLoad(settleIndex, 68)
                let nf2 := frameDataLoad(settleIndex, 100)
                let oc1 := frameDataLoad(settleIndex, 132)
                let oc2 := frameDataLoad(settleIndex, 164)
                let pub := frameDataLoad(settleIndex, 196)
                let fee := frameDataLoad(settleIndex, 228)
                let ctx := frameDataLoad(settleIndex, 260)
                if iszero(nf1) { fail(errZeroNullifier()) }
                if iszero(nf2) { fail(errZeroNullifier()) }
                if iszero(eq(dom, domainVal())) { fail(errInvalidDomain()) }
                let P := fieldP()
                if iszero(lt(root, P)) { fail(errNotCanonical()) }
                if iszero(lt(nf1, P)) { fail(errNotCanonical()) }
                if iszero(lt(nf2, P)) { fail(errNotCanonical()) }
                if iszero(lt(oc1, P)) { fail(errNotCanonical()) }
                if iszero(lt(oc2, P)) { fail(errNotCanonical()) }
                if iszero(lt(dom, P)) { fail(errNotCanonical()) }
                if iszero(lt(ctx, P)) { fail(errNotCanonical()) }
                if iszero(lt(pub, maxValue())) { fail(errValueTooLarge()) }
                if iszero(lt(fee, maxValue())) { fail(errValueTooLarge()) }
                // build verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[9])
                // at 0x80 (keep 0x00..0x80 scratch free).
                let m := 0x80
                mstore(m, shl(224, 0xc542c93b))
                // pA,pB,pC = 8 words from the settle-frame proof region (offset 292).
                for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                    mstore(add(add(m, 0x04), mul(i, 0x20)), frameDataLoad(settleIndex, add(292, mul(i, 0x20))))
                }
                // input[9] in the circuit's public-signal order.
                mstore(add(m, 0x104), nf1)
                mstore(add(m, 0x124), nf2)
                mstore(add(m, 0x144), oc1)
                mstore(add(m, 0x164), oc2)
                mstore(add(m, 0x184), root)
                mstore(add(m, 0x1a4), dom)
                mstore(add(m, 0x1c4), pub)
                mstore(add(m, 0x1e4), fee)
                mstore(add(m, 0x204), ctx)
                let ver := verifierAddr()
                let ok := staticcall(500000, ver, m, 0x224, 0x00, 0x20)
                if iszero(ok) { fail(errProofInvalid()) }
                if iszero(eq(mload(0x00), 1)) { fail(errProofInvalid()) }
            }

            // ================= frame-0 VERIFY as the sender =================
            // Empty-calldata invocation is the frame-0 execution-scope VERIFY
            // frame targeting the sender (this pool). The core two-frame shape
            // approves execution and payment here, so the pool is both sender
            // and payer. The optional three-frame shape approves execution here
            // and lets a separate paymaster approve payment in frame 1.
            function verifyFrameApprove() {
                // envelope: this pool is the sender and the frame-0 target
                if iszero(eq(txParam(0x02), address())) { fail(errNotFaithfulShape()) }
                let frames := txParam(0x09)
                let settleIndex := 0
                let selfPay := 0
                switch frames
                case 2 { settleIndex := 1 selfPay := 1 }
                case 3 { settleIndex := 2 }
                default { fail(errNotFaithfulShape()) }
                if txParam(0x0A) { fail(errKeySetMismatch()) } // nonce_seq == 0
                if iszero(eq(txParam(0x0B), 1)) { fail(errRootNotBound()) } // one recent-root ref
                if txParam(0x07) { fail(errNotFaithfulShape()) } // no blobs
                if iszero(eq(txParam(0x0D), 2)) { fail(errKeySetMismatch()) } // two nonce keys
                if txParam(0x01) { fail(errNotFaithfulShape()) }
                if iszero(eq(txParam(0x0F), 1)) { fail(errNotFaithfulShape()) } // one signature
                // frame 0: VERIFY(this), empty, zero-value. It is combined
                // execution+payment in the core shape and execution-only when
                // an optional paymaster follows.
                if iszero(eq(frameParam(0, 0x00), address())) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(0, 0x02), 1)) { fail(errNotFaithfulShape()) }
                if frameParam(0, 0x04) { fail(errNotFaithfulShape()) }
                if frameParam(0, 0x08) { fail(errNotFaithfulShape()) }
                switch selfPay
                case 1 {
                    if iszero(eq(frameParam(0, 0x03), 3)) { fail(errNotFaithfulShape()) }
                    if iszero(eq(frameParam(0, 0x01), 350000)) { fail(errNotFaithfulShape()) }
                }
                default {
                    if iszero(eq(frameParam(0, 0x03), 2)) { fail(errNotFaithfulShape()) }
                    if iszero(eq(frameParam(0, 0x01), 300000)) { fail(errNotFaithfulShape()) }
                    // frame 1: payment-only VERIFY (optional paymaster)
                    if iszero(eq(frameParam(1, 0x02), 1)) { fail(errNotFaithfulShape()) }
                    if iszero(eq(frameParam(1, 0x03), 1)) { fail(errNotFaithfulShape()) }
                    if iszero(eq(frameParam(1, 0x01), 100000)) { fail(errNotFaithfulShape()) }
                    if frameParam(1, 0x08) { fail(errNotFaithfulShape()) }
                }
                // final frame: the only execution, directly into this pool
                if iszero(eq(frameParam(settleIndex, 0x00), address())) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(settleIndex, 0x02), 2)) { fail(errNotFaithfulShape()) }
                if frameParam(settleIndex, 0x03) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(settleIndex, 0x01), 10000000)) { fail(errNotFaithfulShape()) }
                if frameParam(settleIndex, 0x08) { fail(errNotFaithfulShape()) }
                let dataLen := frameParam(settleIndex, 0x04)
                let selector := shr(224, frameDataLoad(settleIndex, 0))
                switch dataLen
                case 548 {
                    if iszero(eq(selector, 0xb9947fa0)) { fail(errNotFaithfulShape()) } // transfer
                    if frameDataLoad(settleIndex, 196) { fail(errTransferShape()) } // publicAmount == 0
                    if frameDataLoad(settleIndex, 260) { fail(errTransferShape()) } // ctx == 0
                }
                case 580 {
                    if iszero(eq(selector, 0xd677b46e)) { fail(errNotFaithfulShape()) } // withdraw
                    if iszero(frameDataLoad(settleIndex, 196)) { fail(errWithdrawShape()) } // publicAmount > 0
                    let recipient := frameDataLoad(settleIndex, 548)
                    if or(iszero(recipient), shr(160, recipient)) { fail(errWithdrawShape()) }
                    if iszero(eq(frameDataLoad(settleIndex, 260), recipient)) { fail(errCtxRecipient()) } // ctx names recipient
                }
                default { fail(errNotFaithfulShape()) }
                // nonce keys == sorted proof nullifiers
                let nf1 := frameDataLoad(settleIndex, 68)
                let nf2 := frameDataLoad(settleIndex, 100)
                let lo := nf1
                let hi := nf2
                if gt(lo, hi) {
                    lo := nf2
                    hi := nf1
                }
                if iszero(eq(nonceKey(0), lo)) { fail(errKeySetMismatch()) }
                if iszero(eq(nonceKey(1), hi)) { fail(errKeySetMismatch()) }
                // recent-root ref names this pool's source and the proven root
                if iszero(eq(recentRootRef(0, 0), sourceId())) { fail(errRootNotBound()) }
                if iszero(eq(recentRootRef(2, 0), frameDataLoad(settleIndex, 4))) { fail(errRootNotBound()) }
                // Verify the proof INLINE (direct staticcall to the verifier),
                // not via a delegatecall to the implementation: the observer
                // bans delegatecall in a VERIFY frame.
                verifyFrameProof(settleIndex)
                switch selfPay
                case 1 {
                    // The proof removes at least the transaction's maximum gas
                    // liability from note value before the pool pays that cost.
                    if lt(frameDataLoad(settleIndex, 228), txParam(0x06)) { fail(errFeeBelowMaxCost()) }
                    approveExecutionAndPayment()
                }
                default { approveExecution() }
            }

            // ================= dispatch =====================================
            // Empty calldata: the frame-0 VERIFY-as-sender path. Any nonzero
            // calldata is forwarded to the implementation by DELEGATECALL, so
            // it runs in the pool's storage/address/value context.
            if iszero(calldatasize()) {
                verifyFrameApprove()
                stop()
            }

            // Proxy. Resolve the implementation into a local BEFORE clobbering
            // scratch with the calldata copy. The gas argument is a fixed
            // literal, not the GAS opcode: the EVM caps a CALL-family gas
            // request at 63/64 of remaining, so a large literal forwards
            // "almost all" without emitting GAS, keeping the proxy usable both
            // in the ~500k self-staticcall from frame 0 (observer-legal) and in
            // the ~10M SENDER settlement frame.
            let target := impl()
            calldatacopy(0x00, 0x00, calldatasize())
            let ok := delegatecall(0x1c9c380, target, 0x00, calldatasize(), 0x00, 0x00) // 30_000_000
            returndatacopy(0x00, 0x00, returndatasize())
            switch ok
            case 0 { revert(0x00, returndatasize()) }
            default { return(0x00, returndatasize()) }
        }
    }
}
