/// @title ShieldedPool (Yul)
/// @notice The privacy pool IS the transaction sender. Per EIP-8250's design
///         (ACDE #240: "sender = PrivacyPool"), a spend's FrameTx carries
///         sender = this pool, nonce_keys = [nf1, nf2], nonce_seq = 0. One
///         contract is therefore both the frame-0 VERIFY identity that emits
///         APPROVE_EXECUTION and the frame-2 SENDER that settles, so many
///         users share one sender address whose keyed-nonce lanes are their
///         nullifiers. Two spends with disjoint nullifiers occupy disjoint
///         lanes at seq 0 and are includable in the same block.
///
///         This replaces the split ShieldedPool.sol (settlement) +
///         SharedPoolSender.yul (sender identity) with a single Yul object.
///         The code at the sender address must emit the frame-tx opcodes
///         (TXPARAM/FRAMEPARAM/NONCEKEYLOAD/RECENTROOTREFLOAD and
///         APPROVE_EXECUTION), which only standalone Yul objects can
///         (verbatim is unavailable in Solidity and its inline assembly).
///
///         RESEARCH IMPLEMENTATION. This monolithic Yul pool exists to
///         demonstrate pool-as-sender end to end on a disposable devnet with
///         no meaningful funds. It is NOT the preferred production
///         architecture: only the opcode-facing shell must be Yul, so a
///         production deployment should prefer a thin immutable Yul
///         dispatcher at the pool address that handles frame opcodes and
///         DELEGATECALLs settlement to the audited Solidity implementation
///         (EIP-8141 permits helper contracts and DELEGATECALL during
///         validation when they add no mutable-state dependency). The
///         monolith's equivalence to ShieldedPool.sol is enforced by the
///         ported suite (YulShieldedPool.t.sol) and the differential fuzz
///         harness (YulPoolDifferential.t.sol), which treat the Solidity
///         implementation as the spec.
///
///         Errors and events mirror ShieldedPool.sol exactly (same selectors,
///         same topics, same emission order): the forge suite asserts the
///         named reverts, and the wallet tooling reconstructs the tree from
///         LeafAppended, so both are part of the contract's interface.
///
///         Poseidon (t=3, t=4) and the Groth16 verifier stay as the existing
///         deployed, tested contracts, called here; the field/tree/proof
///         constants are unchanged. Settlement still reads envelope facts
///         through the mockable EnvelopeProbe staticcall so the forge suite
///         remains the settlement oracle; the frame-0 verify+approve reads the
///         envelope opcodes directly and is validated live, exactly as
///         SharedPoolSender was.
///
///         Deploy: initcode tail = poseidonT3|poseidonT4|verifier|probe (four
///         32-byte words), appended to the deployed runtime as immutables.
object "ShieldedPool" {
    code {
        // ---- constructor ----
        // currentRoot = zeros(DEPTH); publish it once; return runtime||tail.
        let zeroRoot := 0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e
        sstore(22, zeroRoot)
        // publish SALT(0)||root to the EIP-8272 predeploy (no-op success on
        // forge/anvil; a native 64-byte write on ethrex).
        mstore(0, 0)
        mstore(32, zeroRoot)
        if iszero(call(gas(), 0x8272, 0, 0, 64, 0, 0)) {
            mstore(0, shl(224, 0x5c3c03e8)) // RootPublishFailed()
            revert(0, 4)
        }

        let rsize := datasize("runtime")
        // move the four appended immutables (128 bytes) to sit right after the
        // runtime image, then lay the runtime image at 0 and return both.
        codecopy(rsize, sub(codesize(), 128), 128)
        datacopy(0, dataoffset("runtime"), rsize)
        return(0, add(rsize, 128))
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

            // ================= constants =====================================
            function fieldP() -> v { v := 21888242871839275222246405745257275088548364400416034343698204186575808495617 }
            function maxValue() -> v { v := 0x100000000000000000000000000000000 } // 1 << 128
            function domainTag() -> v { v := 0x40752e102d2a749c61d42a71e297edd3b493de639003b9480a700d589d98065b }
            function depth() -> v { v := 20 }

            // ================= named errors (ShieldedPool.sol selectors) =====
            function fail(sel) {
                mstore(0x00, shl(224, sel))
                revert(0x00, 0x04)
            }
            function errZeroValueShield() -> s { s := 0x63c81d05 }
            function errValueTooLarge() -> s { s := 0x2ad907fb }
            function errDuplicateCommitment() -> s { s := 0xe43a58fa }
            function errNotCanonical() -> s { s := 0xd7c7beeb }
            function errTreeFull() -> s { s := 0xb48f2cf8 }
            function errNotPoolSender() -> s { s := 0xedce9792 }
            function errZeroNullifier() -> s { s := 0xcbbbbfe1 }
            function errNotFrameNative() -> s { s := 0xf8171c6f }
            function errNotFaithfulShape() -> s { s := 0xe6d22e28 }
            function errRootNotBound() -> s { s := 0xaf501e1c } // RootNotBoundToReference()
            function errProofInvalid() -> s { s := 0x7fcdd1f4 }
            function errInvalidDomain() -> s { s := 0xeb127982 }
            function errKeySetMismatch() -> s { s := 0x586e51ed }
            function errTransferShape() -> s { s := 0xef7a30fa }
            function errWithdrawShape() -> s { s := 0x7f54f5ab }
            function errCtxRecipient() -> s { s := 0x49cb8b3a } // CtxDoesNotNameRecipient()
            function errPayoutFailed() -> s { s := 0x3b1ab104 }
            function errZeroFeeRecipient() -> s { s := 0xcff9f194 }
            function errNoCredit() -> s { s := 0x315b0e14 }
            function errRootPublishFailed() -> s { s := 0x5c3c03e8 }

            // ================= events (ShieldedPool.sol topics) ==============
            // LeafAppended(bytes32 indexed cm, uint32 index, bytes32 newRoot, uint64 slot)
            function emitLeafAppended(cm, index, newRoot) {
                mstore(0x00, index)
                mstore(0x20, newRoot)
                mstore(0x40, number())
                log2(0x00, 0x60, 0xfabf38c5739db32d58c40511e4e5842cad3db03f7058bffea44ce500c8664106, cm)
            }
            // NoteSpent(bytes32 indexed nf)
            function emitNoteSpent(nf) {
                log2(0x00, 0x00, 0xd13faa8100906cf559aebacf9c16532cfc9708645c198c8f15798ee049dbcfc1, nf)
            }
            // Withdrawn(address indexed recipient, uint256 amount)
            function emitWithdrawn(who, amount) {
                mstore(0x00, amount)
                log2(0x00, 0x20, 0x7084f5476618d8e60b11ef0d7d3f06914655adb8793e28ff7f018d4c76d505d5, who)
            }
            // FeePaid(address indexed to, uint256 amount)
            function emitFeePaid(who, amount) {
                mstore(0x00, amount)
                log2(0x00, 0x20, 0x075a2720282fdf622141dae0b048ef90a21a7e57c134c76912d19d006b3b3f6f, who)
            }
            // WithdrawalCredited(address indexed recipient, uint256 amount)
            function emitWithdrawalCredited(who, amount) {
                mstore(0x00, amount)
                log2(0x00, 0x20, 0x459f560336b72d57e46610439b7c1a8426cf7b7a2a0428d5fb5c7b0b7528b60d, who)
            }
            // FeeCredited(address indexed recipient, uint256 amount)
            function emitFeeCredited(who, amount) {
                mstore(0x00, amount)
                log2(0x00, 0x20, 0x45a4008fdcdf7099dada51fcbfc5c09dc509d6c44e84ba8f052a166eb1d11adf, who)
            }

            // ================= immutables (appended tail) ====================
            function immAt(fromEnd) -> a {
                codecopy(0x00, sub(codesize(), fromEnd), 32)
                a := and(mload(0x00), 0xffffffffffffffffffffffffffffffffffffffff)
            }
            function poseidonT3() -> a { a := immAt(128) }
            function poseidonT4() -> a { a := immAt(96) }
            function verifierAddr() -> a { a := immAt(64) }
            function probeAddr() -> a { a := immAt(32) }

            // ================= Poseidon (external library calls) =============
            // circomlib Poseidon, deployed as Solidity libraries. They are pure
            // and read no storage, so a plain CALL runs them in their own
            // context and returns the hash (verified against the reference).
            // Scratch memory 0x00.. is clobbered; callers must not hold live
            // values there across a hash.
            // Resolve the library address into a local BEFORE writing the
            // call buffer: immAt() uses scratch 0x00, which is where the
            // selector lives, so resolving it inline would clobber the
            // selector and send 0x00000000.
            function hash2(x0, x1) -> out {
                let lib := poseidonT3()
                mstore(0x00, shl(224, 0x511c53ff)) // hash2(uint256,uint256)
                mstore(0x04, x0)
                mstore(0x24, x1)
                if iszero(call(gas(), lib, 0, 0x00, 0x44, 0x00, 0x20)) { revert(0, 0) }
                out := mload(0x00)
            }
            function hash3(x0, x1, x2) -> out {
                let lib := poseidonT4()
                mstore(0x00, shl(224, 0x2dbf86c6)) // hash3(uint256,uint256,uint256)
                mstore(0x04, x0)
                mstore(0x24, x1)
                mstore(0x44, x2)
                if iszero(call(gas(), lib, 0, 0x00, 0x64, 0x00, 0x20)) { revert(0, 0) }
                out := mload(0x00)
            }

            // ================= zeros(l): empty-subtree roots =================
            function zeros(l) -> z {
                switch l
                case 0 { z := 0 }
                case 1 { z := 0x2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864 }
                case 2 { z := 0x1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1 }
                case 3 { z := 0x18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238 }
                case 4 { z := 0x07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a }
                case 5 { z := 0x2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55 }
                case 6 { z := 0x2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78 }
                case 7 { z := 0x078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d }
                case 8 { z := 0x2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61 }
                case 9 { z := 0x0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747 }
                case 10 { z := 0x1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2 }
                case 11 { z := 0x1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636 }
                case 12 { z := 0x2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a }
                case 13 { z := 0x14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0 }
                case 14 { z := 0x190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c }
                case 15 { z := 0x22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92 }
                case 16 { z := 0x2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323 }
                case 17 { z := 0x2e8186e558698ec1c67af9c14d463ffc470043c9c2988b954d75dd643f36b992 }
                case 18 { z := 0x0f57c5571e9a4eab49e2c8cf050dae948aef6ead647392273546249d1c1ff10f }
                case 19 { z := 0x1830ee67b5fb554ad5f63d4388800e1cfe78e310697d46e43c9ce36134f72cca }
                case 20 { z := 0x2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e }
                default { revert(0, 0) }
            }

            // ================= storage helpers ===============================
            // slots: 0..20 filledSubtrees, 21 nextIndex, 22 currentRoot,
            // 23 isLeaf map, 24 withdrawalCredit map, 25 feeCredit map.
            function mapSlot(key, base) -> s {
                mstore(0x00, key)
                mstore(0x20, base)
                s := keccak256(0x00, 0x40)
            }
            function isLeaf(cm) -> v { v := sload(mapSlot(cm, 23)) }
            function setLeaf(cm) { sstore(mapSlot(cm, 23), 1) }
            function withdrawalCredit(a) -> v { v := sload(mapSlot(a, 24)) }
            function feeCredit(a) -> v { v := sload(mapSlot(a, 25)) }

            // ================= identity (pure of address/chain) ==============
            function sourceId() -> id {
                // keccak256(abi.encode(address(this), SALT=0)) == ethrex's
                // native-write source: keccak256(pad32(this) || salt).
                mstore(0x00, address())
                mstore(0x20, 0)
                id := keccak256(0x00, 0x40)
            }
            function domainVal() -> d {
                // keccak256(DOMAIN_TAG || chainId || sourceId) % P.
                // Resolve sourceId into a local FIRST: it uses scratch
                // 0x00..0x40 for its own keccak and would clobber the buffer.
                let src := sourceId()
                mstore(0x00, domainTag())
                mstore(0x20, chainid())
                mstore(0x40, src)
                d := mod(keccak256(0x00, 0x60), fieldP())
            }
            function ctxFor(a) -> c { c := and(a, 0xffffffffffffffffffffffffffffffffffffffff) }

            // ================= incremental Merkle tree ======================
            function insert(cm) -> index {
                index := sload(21)
                if iszero(lt(index, shl(depth(), 1))) { fail(errTreeFull()) }
                sstore(21, add(index, 1))
                setLeaf(cm)
                let node := cm
                let idx := index
                let l := 0
                for {} eq(and(idx, 1), 1) {} {
                    node := hash2(sload(l), node)
                    idx := shr(1, idx)
                    l := add(l, 1)
                }
                sstore(l, node) // l == DEPTH only for the leaf that fills the tree
            }
            function computeRoot() -> node {
                let idx := sload(21)
                switch eq(idx, shl(depth(), 1))
                case 1 { node := sload(depth()) }
                default {
                    let l := 0
                    for {} lt(l, depth()) { l := add(l, 1) } {
                        switch and(idx, 1)
                        case 0 { node := hash2(node, zeros(l)) }
                        default { node := hash2(sload(l), node) }
                        idx := shr(1, idx)
                    }
                }
            }
            function publishRoot() {
                mstore(0x00, 0) // SALT
                mstore(0x20, sload(22))
                if iszero(call(gas(), 0x8272, 0, 0x00, 0x40, 0x00, 0x00)) { fail(errRootPublishFailed()) }
            }

            // ================= proof verification ============================
            // Reads the Spend at calldata offset `base` (base=4 for a direct
            // call, since Spend is a static 544-byte tuple). These cheap checks
            // stay in settlement even though proof verification happens once,
            // in frame 0: they preserve canonical ABI/state behavior without a
            // second pairing call. No storage reads.
            function validateSpend(base) {
                let root := calldataload(add(base, 0))
                let dom := calldataload(add(base, 32))
                let nf1 := calldataload(add(base, 64))
                let nf2 := calldataload(add(base, 96))
                let oc1 := calldataload(add(base, 128))
                let oc2 := calldataload(add(base, 160))
                let pub := calldataload(add(base, 192))
                let fee := calldataload(add(base, 224))
                let ctx := calldataload(add(base, 256))
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
            }

            // Canonical/range checks plus Groth16 over the nine public signals.
            // Called by verifyProofOnly from the authenticated frame-0 path.
            function verifySpend(base) {
                validateSpend(base)
                let root := calldataload(add(base, 0))
                let dom := calldataload(add(base, 32))
                let nf1 := calldataload(add(base, 64))
                let nf2 := calldataload(add(base, 96))
                let oc1 := calldataload(add(base, 128))
                let oc2 := calldataload(add(base, 160))
                let pub := calldataload(add(base, 192))
                let fee := calldataload(add(base, 224))
                let ctx := calldataload(add(base, 256))
                // build verifyProof(uint256[2] a, uint256[2][2] b, uint256[2] c,
                // uint256[9] input) at mem 0x80 (keep 0x00..0x80 scratch free).
                let m := 0x80
                mstore(m, shl(224, 0xc542c93b))
                calldatacopy(add(m, 0x04), add(base, 288), 256) // pA,pB,pC = 8 words
                // input[9] in the circuit's public-signal order
                mstore(add(m, 0x104), nf1)
                mstore(add(m, 0x124), nf2)
                mstore(add(m, 0x144), oc1)
                mstore(add(m, 0x164), oc2)
                mstore(add(m, 0x184), root)
                mstore(add(m, 0x1a4), dom)
                mstore(add(m, 0x1c4), pub)
                mstore(add(m, 0x1e4), fee)
                mstore(add(m, 0x204), ctx)
                // fixed gas literal (500k), not gas(): the ERC-7562 validation
                // observer bans the GAS opcode in a VERIFY frame. Resolve the
                // verifier before the staticcall (immAt uses scratch 0x00).
                let ver := verifierAddr()
                let ok := staticcall(500000, ver, m, 0x224, 0x00, 0x20)
                if iszero(ok) { fail(errProofInvalid()) }
                if iszero(eq(mload(0x00), 1)) { fail(errProofInvalid()) }
            }

            // ================= settlement (frame-2 SENDER) ==================
            // Envelope facts via the mockable probe (staticcall, 320-byte
            // return). The keyed nonces were consumed by the protocol at
            // payment approval; this checks THIS tx consumed exactly the proven
            // nullifiers, the proven root rode as the recent-root reference,
            // nullifiers and the proven root rode as the recent-root reference.
            // Proof validity was authenticated over this exact frame-2 tuple by
            // the pool's frame-0 code before APPROVE_EXECUTION. msg.sender must
            // be the pool itself, so the frame-2 self-call has caller() == address().
            function spendCheck(base) {
                if iszero(eq(caller(), address())) { fail(errNotPoolSender()) }
                let nf1 := calldataload(add(base, 64))
                let nf2 := calldataload(add(base, 96))
                if iszero(nf1) { fail(errZeroNullifier()) }
                if iszero(nf2) { fail(errZeroNullifier()) }
                // probe.staticcall("") -> 10 words, gas-capped
                let ok := staticcall(100000, probeAddr(), 0x00, 0x00, 0x00, 0x00)
                if iszero(ok) { fail(errNotFrameNative()) }
                if iszero(eq(returndatasize(), 320)) { fail(errNotFrameNative()) }
                returndatacopy(0x80, 0, 320)
                let frames := mload(0x80)
                let frameIndex := mload(0xa0)
                let keyCount := mload(0xc0)
                let nonceSeq := mload(0xe0)
                let k0 := mload(0x100)
                let k1 := mload(0x120)
                let refCount := mload(0x140)
                let refSource := mload(0x160)
                let refRoot := mload(0x180)
                let settleTarget := and(mload(0x1a0), 0xffffffffffffffffffffffffffffffffffffffff)
                if or(or(iszero(eq(frames, 3)), iszero(eq(frameIndex, 2))),
                       iszero(eq(settleTarget, address()))) { fail(errNotFaithfulShape()) }
                // consumed key set == proven nullifiers, sorted {lo, hi}
                let lo := nf1
                let hi := nf2
                if gt(lo, hi) { lo := nf2 hi := nf1 }
                if or(or(iszero(eq(keyCount, 2)), iszero(eq(nonceSeq, 0))),
                       or(iszero(eq(k0, lo)), iszero(eq(k1, hi)))) { fail(errKeySetMismatch()) }
                let root := calldataload(add(base, 0))
                if or(or(iszero(eq(refCount, 1)), iszero(eq(refSource, sourceId()))),
                       iszero(eq(refRoot, root))) { fail(errRootNotBound()) }
                validateSpend(base)
                emitNoteSpent(nf1)
                emitNoteSpent(nf2)
            }

            // Insert the two output notes (duplicate = no-op), recompute+publish
            // once, then record the fee as a pull credit for feeRecipient.
            function settle(base, feeRecipient) {
                let oc1 := calldataload(add(base, 128))
                let oc2 := calldataload(add(base, 160))
                let fee := calldataload(add(base, 224))
                let new1 := iszero(isLeaf(oc1))
                let i1 := 0
                if new1 { i1 := insert(oc1) }
                let new2 := iszero(isLeaf(oc2))
                let i2 := 0
                if new2 { i2 := insert(oc2) }
                if or(new1, new2) {
                    let newRoot := computeRoot()
                    sstore(22, newRoot)
                    if new1 { emitLeafAppended(oc1, i1, newRoot) }
                    if new2 { emitLeafAppended(oc2, i2, newRoot) }
                }
                publishRoot()
                if iszero(iszero(fee)) {
                    if iszero(feeRecipient) { fail(errZeroFeeRecipient()) }
                    let s := mapSlot(feeRecipient, 25)
                    sstore(s, add(sload(s), fee))
                    emitFeeCredited(feeRecipient, fee)
                }
            }

            // ================= view returns =================================
            function ret(v) { mstore(0x00, v) return(0x00, 0x20) }

            // ================= Solidity ABI decoder parity ==================
            // The Solidity pool's generated decoder enforces, before any body
            // code runs: a minimum argument length (extra trailing bytes are
            // accepted), canonical address words (high 96 bits zero reverts,
            // never masked), and zero callvalue on non-payable functions. All
            // three revert with empty data, matching solc's codegen.
            function needArgs(n) { if lt(sub(calldatasize(), 4), n) { revert(0, 0) } }
            function addrArg(off) -> a {
                a := calldataload(off)
                if shr(160, a) { revert(0, 0) }
            }

            // ================= frame-0 VERIFY as the sender =================
            // Empty-calldata invocation is the frame-0 execution-scope VERIFY
            // frame targeting the sender (this pool). Reads the Spend from the
            // frame-2 SENDER calldata, authenticates grammar, the exact keyed
            // nonces and the recent-root reference, verifies the proof, and
            // emits APPROVE_EXECUTION. Reads the frame opcodes directly (no
            // probe): validated live, not on forge. Reverts reuse the pool's
            // named error selectors so a validation-prefix simulation failure
            // is attributable from the RPC error alone.
            function verifyFrameApprove() {
                // envelope: this pool is the sender and the frame-0 target
                if iszero(eq(txParam(0x02), address())) { fail(errNotFaithfulShape()) }
                if iszero(eq(txParam(0x09), 3)) { fail(errNotFaithfulShape()) }
                if txParam(0x0A) { fail(errKeySetMismatch()) }        // nonce_seq == 0
                if iszero(eq(txParam(0x0B), 1)) { fail(errRootNotBound()) } // one recent-root ref
                if txParam(0x07) { fail(errNotFaithfulShape()) }      // no blobs
                if iszero(eq(txParam(0x0D), 2)) { fail(errKeySetMismatch()) } // two nonce keys
                if txParam(0x01) { fail(errNotFaithfulShape()) }
                if iszero(eq(txParam(0x0F), 1)) { fail(errNotFaithfulShape()) } // one signature
                // frame 0: VERIFY(this), execution-only, empty, zero-value
                if iszero(eq(frameParam(0, 0x00), address())) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(0, 0x02), 1)) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(0, 0x03), 2)) { fail(errNotFaithfulShape()) }
                if frameParam(0, 0x04) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(0, 0x01), 300000)) { fail(errNotFaithfulShape()) }
                if frameParam(0, 0x08) { fail(errNotFaithfulShape()) }
                // frame 1: payment-only VERIFY (the paymaster)
                if iszero(eq(frameParam(1, 0x02), 1)) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(1, 0x03), 1)) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(1, 0x01), 100000)) { fail(errNotFaithfulShape()) }
                if frameParam(1, 0x08) { fail(errNotFaithfulShape()) }
                // frame 2: the only execution, directly into this pool
                if iszero(eq(frameParam(2, 0x00), address())) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(2, 0x02), 2)) { fail(errNotFaithfulShape()) }
                if frameParam(2, 0x03) { fail(errNotFaithfulShape()) }
                if iszero(eq(frameParam(2, 0x01), 10000000)) { fail(errNotFaithfulShape()) }
                if frameParam(2, 0x08) { fail(errNotFaithfulShape()) }
                let dataLen := frameParam(2, 0x04)
                let selector := shr(224, frameDataLoad(2, 0))
                switch dataLen
                case 580 {
                    if iszero(eq(selector, 0x751a8fc5)) { fail(errNotFaithfulShape()) } // transfer
                    if frameDataLoad(2, 196) { fail(errTransferShape()) }  // publicAmount == 0
                    if frameDataLoad(2, 260) { fail(errTransferShape()) }  // ctx == 0
                    let fr := frameDataLoad(2, 548)
                    if or(iszero(fr), shr(160, fr)) { fail(errZeroFeeRecipient()) }
                }
                case 612 {
                    if iszero(eq(selector, 0x215ae4c7)) { fail(errNotFaithfulShape()) } // withdraw
                    if iszero(frameDataLoad(2, 196)) { fail(errWithdrawShape()) }    // publicAmount > 0
                    let recipient := frameDataLoad(2, 548)
                    if or(iszero(recipient), shr(160, recipient)) { fail(errWithdrawShape()) }
                    if iszero(eq(frameDataLoad(2, 260), recipient)) { fail(errCtxRecipient()) } // ctx names recipient
                    let fr := frameDataLoad(2, 580)
                    if or(iszero(fr), shr(160, fr)) { fail(errZeroFeeRecipient()) }
                }
                default { fail(errNotFaithfulShape()) }
                // nonce keys == sorted proof nullifiers
                let nf1 := frameDataLoad(2, 68)
                let nf2 := frameDataLoad(2, 100)
                let lo := nf1
                let hi := nf2
                if gt(lo, hi) { lo := nf2 hi := nf1 }
                if iszero(eq(nonceKey(0), lo)) { fail(errKeySetMismatch()) }
                if iszero(eq(nonceKey(1), hi)) { fail(errKeySetMismatch()) }
                // recent-root ref names this pool's source and the proven root
                if iszero(eq(recentRootRef(0, 0), sourceId())) { fail(errRootNotBound()) }
                if iszero(eq(recentRootRef(2, 0), frameDataLoad(2, 4))) { fail(errRootNotBound()) }
                // verify the proof by self-staticcall to verifyProofOnly, built
                // from frame 2 (Spend static tuple at [4, 548)).
                mstore(0x80, shl(224, 0x8cc8fe8d))
                for { let off := 4 } lt(off, 548) { off := add(off, 32) } {
                    mstore(add(0x80, off), frameDataLoad(2, off))
                }
                if iszero(staticcall(500000, address(), 0x80, 548, 0x00, 0x00)) { fail(errProofInvalid()) }
                approveExecution()
            }

            // ================= dispatch =====================================
            // Empty calldata: the frame-0 VERIFY-as-sender path. Any nonzero
            // calldata dispatches by selector. The frame opcodes exceptional-
            // halt outside a frame transaction, so a stray empty CALL reverts.
            if iszero(calldatasize()) {
                verifyFrameApprove()
                stop()
            }

            let sel := shr(224, calldataload(0))
            // non-payable parity: only shield accepts value (solc emits this
            // callvalue guard for every non-payable function).
            if callvalue() { if iszero(eq(sel, 0x26123548)) { revert(0, 0) } }
            switch sel
            case 0x26123548 { // shield(bytes32) payable -> uint32 index
                needArgs(32)
                if iszero(callvalue()) { fail(errZeroValueShield()) }
                if iszero(lt(callvalue(), maxValue())) { fail(errValueTooLarge()) }
                let inner := calldataload(4)
                if iszero(lt(inner, fieldP())) { fail(errNotCanonical()) }
                let cm := hash3(2, inner, callvalue())
                if isLeaf(cm) { fail(errDuplicateCommitment()) }
                let index := insert(cm)
                let newRoot := computeRoot()
                sstore(22, newRoot)
                emitLeafAppended(cm, index, newRoot)
                publishRoot()
                ret(index)
            }
            case 0x751a8fc5 { // transfer(Spend,address)
                needArgs(576)
                let feeRecipient := addrArg(548)
                if or(iszero(iszero(calldataload(196))), iszero(iszero(calldataload(260)))) { fail(errTransferShape()) } // publicAmount==0 && ctx==0
                spendCheck(4)
                settle(4, feeRecipient)
                stop()
            }
            case 0x215ae4c7 { // withdraw(Spend,address recipient,address feeRecipient)
                needArgs(608)
                let recipient := addrArg(548)
                let feeRecipient := addrArg(580)
                let pub := calldataload(196)
                let ctx := calldataload(260)
                if or(iszero(pub), iszero(ctx)) { fail(errWithdrawShape()) }
                if iszero(eq(ctx, ctxFor(recipient))) { fail(errCtxRecipient()) }
                spendCheck(4)
                settle(4, feeRecipient)
                // withdrawalCredit[recipient] += publicAmount
                let s := mapSlot(recipient, 24)
                sstore(s, add(sload(s), pub))
                emitWithdrawalCredited(recipient, pub)
                stop()
            }
            case 0x8cc8fe8d { // verifyProofOnly(Spend) view
                needArgs(544)
                if iszero(calldataload(68)) { fail(errZeroNullifier()) } // nf1
                if iszero(calldataload(100)) { fail(errZeroNullifier()) } // nf2
                verifySpend(4)
                stop()
            }
            case 0xa3066aab { // claimWithdrawal(address payable who)
                needArgs(32)
                let who := addrArg(4)
                let s := mapSlot(who, 24)
                let amount := sload(s)
                if iszero(amount) { fail(errNoCredit()) }
                sstore(s, 0)
                emitWithdrawn(who, amount)
                if iszero(call(gas(), who, amount, 0, 0, 0, 0)) { fail(errPayoutFailed()) }
                stop()
            }
            case 0x6ebc51e1 { // claimFee(address payable who)
                needArgs(32)
                let who := addrArg(4)
                let s := mapSlot(who, 25)
                let amount := sload(s)
                if iszero(amount) { fail(errNoCredit()) }
                sstore(s, 0)
                emitFeePaid(who, amount)
                if iszero(call(gas(), who, amount, 0, 0, 0, 0)) { fail(errPayoutFailed()) }
                stop()
            }
            case 0xfdab463d { ret(sload(22)) }                 // currentRoot()
            case 0xd069aab9 { ret(sourceId()) }                // sourceId()
            case 0xc2fb26a6 { ret(domainVal()) }               // domain()
            case 0xfc7e9c6f { ret(sload(21)) }                 // nextIndex()
            case 0xb83b3026 { // isLeaf(bytes32)
                needArgs(32)
                ret(isLeaf(calldataload(4)))
            }
            case 0x0a5570fa { // withdrawalCredit(address)
                needArgs(32)
                ret(withdrawalCredit(addrArg(4)))
            }
            case 0x5c584c88 { // feeCredit(address)
                needArgs(32)
                ret(feeCredit(addrArg(4)))
            }
            case 0xf178e47c { // filledSubtrees(uint256), bytes32[DEPTH+1]: 0..20
                needArgs(32)
                let i := calldataload(4)
                if gt(i, depth()) { revert(0, 0) }
                ret(sload(i))
            }
            case 0x02f36d86 { // ctxFor(address)
                needArgs(32)
                ret(ctxFor(addrArg(4)))
            }
            case 0x7bb5421b { // domainFor(uint256 chainId, bytes32 source)
                needArgs(64)
                mstore(0x00, domainTag())
                mstore(0x20, calldataload(4))
                mstore(0x40, calldataload(36))
                ret(mod(keccak256(0x00, 0x60), fieldP()))
            }
            case 0xb74af5a9 { ret(probeAddr()) }                // probe()
            case 0x2b7ac3f3 { ret(verifierAddr()) }             // verifier()
            case 0x98366e35 { ret(depth()) }                    // DEPTH()
            case 0xba9a91a5 { ret(0) }                          // SALT()
            case 0xe32e13eb { ret(domainTag()) }                // DOMAIN_TAG()
            case 0x94e5fa12 { ret(0x8272) }                     // RECENT_ROOT_PREDEPLOY()
            case 0xa8a5337b { ret(address()) }                  // POOL_SENDER() == the pool itself
            default { revert(0, 0) }
        }
    }
}
