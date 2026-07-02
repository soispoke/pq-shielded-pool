// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title NonceManager — EIP-8250 keyed nonces, emulated for Sepolia
/// @notice The load-bearing property is preserved exactly: key domains are
///         PER SENDER. `slot(sender, key) = keccak256(left_pad_32(sender) || key)`
///         per the EIP, an absent slot reads as sequence 0, and consumption
///         writes seq + 1. The same key under two senders is two independent
///         slots, which is why the pool pins one POOL_SENDER (see
///         devnet/README.md). On the real devnet this contract is the
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

    /// Consume `key` for `sender` at sequence 0 (a fresh single-use key, the
    /// nullifier pattern). Reverts if the key was already used for this sender.
    function consumeFresh(address sender, bytes32 key) external {
        if (msg.sender != pool) revert NotPool();
        bytes32 s = slotOf(sender, key);
        if (seq[s] != 0) revert NonceKeyAlreadyUsed();
        seq[s] = 1;
    }
}
