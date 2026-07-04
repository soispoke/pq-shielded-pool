// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title NonceManager — EIP-8250 keyed nonces, emulated for Sepolia
/// @notice The load-bearing property is preserved exactly: key domains are
///         PER SENDER. `slot(sender, key) = keccak256(left_pad_32(sender) || key)`
///         per the EIP, an absent slot reads as sequence 0, and consumption
///         writes seq + 1. The same key under two senders is two independent
///         slots, which is why the pool pins one POOL_SENDER (see
///         ../devnet/REVIEW.md). On the real devnet this contract is the
///         protocol's NONCE_MANAGER and consumption happens at payment
///         approval; here only the registered pool may consume.
contract NonceManager {
    address public immutable pool;
    mapping(bytes32 => uint64) private seq;

    error NotPool();
    error NonceKeyAlreadyUsed();

    constructor(address pool_) {
        pool = pool_;
    }

    /// EIP-8250 storage slot: keccak256(left_pad_32(sender) || key).
    function slotOf(address sender, bytes32 key) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(bytes32(uint256(uint160(sender))), key));
    }

    function current(address sender, bytes32 key) external view returns (uint64) {
        return seq[slotOf(sender, key)];
    }

    uint256 public constant MAX_NONCE_KEYS = 16;

    error EmptyKeySet();
    error TooManyKeys();
    error ZeroNonceKey();

    /// Consume a SET of keys for `sender`, all at the shared sequence 0, as
    /// one atomic step: the EIP-8250 `nonce_keys` list shape (bounded by
    /// MAX_NONCE_KEYS; zero keys rejected because [0] selects the legacy
    /// account nonce; disjoint non-zero key sets are replay-independent).
    /// A duplicate key in the set trips NonceKeyAlreadyUsed on its second
    /// occurrence, and any failure reverts the whole set, so a multi-input
    /// spend can never half-consume its nullifiers. This is the multi-key
    /// form the join-split pool exercises with two nullifiers.
    function consumeFreshMany(address sender, bytes32[] calldata keys) external {
        if (msg.sender != pool) revert NotPool();
        if (keys.length == 0) revert EmptyKeySet();
        if (keys.length > MAX_NONCE_KEYS) revert TooManyKeys();
        for (uint256 i = 0; i < keys.length; i++) {
            if (keys[i] == bytes32(0)) revert ZeroNonceKey();
            bytes32 s = slotOf(sender, keys[i]);
            if (seq[s] != 0) revert NonceKeyAlreadyUsed();
            seq[s] = 1;
        }
    }
}
