// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title RecentRoots — EIP-8272 recent roots, emulated for Sepolia
/// @notice Storage layout, entry hashing, and the referenceability window
///         follow the EIP: `source_id = keccak256(source_address || salt)`
///         with the source being `msg.sender` of the write, entries stored as
///         `entry_hash = keccak256(ENTRY_DOMAIN || source_id || uint64_be(slot) || root)`
///         at `storage_key = keccak256(STORAGE_DOMAIN || source_id || uint64_be(slot % LENGTH))`,
///         and a root written in slot S referenceable from S+1 through
///         S + USABLE_WINDOW. One emulation substitution: `block.number`
///         stands in for the consensus slot (Sepolia contracts cannot see
///         slots), and `check` is a view the pool calls instead of the
///         protocol's pre-execution reference validation + RECENTROOTREFLOAD.
contract RecentRoots {
    uint256 public constant RECENT_ROOT_LENGTH = 8192;
    uint256 public constant RECENT_ROOT_USABLE_WINDOW = 8191;
    bytes32 public constant ENTRY_DOMAIN = keccak256("RECENT_ROOT_ENTRY");
    bytes32 public constant STORAGE_DOMAIN = keccak256("RECENT_ROOT_STORAGE");

    mapping(bytes32 => bytes32) public entries;

    event RootWritten(bytes32 indexed sourceId, uint64 slot, bytes32 root);

    function sourceIdOf(address source, bytes32 salt) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(source, salt));
    }

    function write(bytes32 salt, bytes32 root) external {
        bytes32 sourceId = sourceIdOf(msg.sender, salt);
        uint64 slot = uint64(block.number);
        bytes32 entryHash = keccak256(abi.encodePacked(ENTRY_DOMAIN, sourceId, slot, root));
        bytes32 storageKey =
            keccak256(abi.encodePacked(STORAGE_DOMAIN, sourceId, uint64(slot % RECENT_ROOT_LENGTH)));
        entries[storageKey] = entryHash;
        emit RootWritten(sourceId, slot, root);
    }

    /// A recent root (source_id, slot, root) is valid iff the slot is within
    /// the usable window strictly before the current slot and the stored
    /// entry commits to exactly this tuple.
    function check(bytes32 sourceId, uint64 slot, bytes32 root) external view returns (bool) {
        uint256 current = block.number;
        if (current <= slot || current - slot > RECENT_ROOT_USABLE_WINDOW) return false;
        bytes32 entryHash = keccak256(abi.encodePacked(ENTRY_DOMAIN, sourceId, slot, root));
        bytes32 storageKey =
            keccak256(abi.encodePacked(STORAGE_DOMAIN, sourceId, uint64(slot % RECENT_ROOT_LENGTH)));
        return entries[storageKey] == entryHash;
    }
}
