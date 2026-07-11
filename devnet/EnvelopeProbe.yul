/// @title EnvelopeProbe
/// @notice Stateless frame-transaction envelope reader for the settle-only
///         pool. Solidity cannot emit the EIP-8141/8250/8272 introspection
///         opcodes (verbatim is Yul-object-only), so ShieldedPool._spend
///         STATICCALLs this contract and binds the nine returned words:
///
///           [0] frame count            TXPARAM 0x09
///           [1] current frame index    TXPARAM 0x0A
///           [2] nonce-key count        TXPARAM 0x0D
///           [3] nonce_seq              TXPARAM 0x01
///           [4] nonce_keys[0]          NONCEKEYLOAD 0xB9 (0 when count == 0)
///           [5] nonce_keys[1]          NONCEKEYLOAD 0xB9 (0 when count <= 1)
///           [6] recent-root ref count  TXPARAM 0x0F
///           [7] ref[0].source_id       RECENTROOTREFLOAD 0xB5 (0 when none)
///           [8] ref[0].root            RECENTROOTREFLOAD 0xB5 (0 when none)
///
///         Guarded reads: the load opcodes exceptional-halt out of range, so
///         keys/refs are read only when the counts cover them. Outside a
///         frame transaction TXPARAM itself halts, consuming the forwarded
///         gas — callers cap it (the pool forwards 60k) and treat the failed
///         call as "not frame-native". No storage, no calldata, no state.
object "EnvelopeProbe" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            function txParam(param) -> value {
                value := verbatim_1i_1o(hex"B0", param)
            }
            mstore(0, txParam(0x09))
            mstore(32, txParam(0x0A))
            let keyCount := txParam(0x0D)
            mstore(64, keyCount)
            mstore(96, txParam(0x01))
            if gt(keyCount, 0) { mstore(128, verbatim_1i_1o(hex"B9", 0)) }
            if gt(keyCount, 1) { mstore(160, verbatim_1i_1o(hex"B9", 1)) }
            let refCount := txParam(0x0F)
            mstore(192, refCount)
            if gt(refCount, 0) {
                // RECENTROOTREFLOAD pops field first (stack top), then index.
                mstore(224, verbatim_2i_1o(hex"B5", 0, 0)) // field 0: source_id
                mstore(256, verbatim_2i_1o(hex"B5", 2, 0)) // field 2: root
            }
            return(0, 288)
        }
    }
}
