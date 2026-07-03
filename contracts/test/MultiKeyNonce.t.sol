// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {NonceManager} from "../src/NonceManager.sol";

interface Vm {
    function prank(address) external;
    function expectRevert(bytes4) external;
}

/// Unit tests for the EIP-8250 multi-key set semantics in isolation: shared
/// nonce_seq = 0, atomic all-or-nothing consumption, per-sender domains,
/// duplicate and zero keys refused, MAX_NONCE_KEYS bound. This test contract
/// registers itself as the pool so it can drive consumption directly.
contract MultiKeyNonceTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    NonceManager nm;
    address constant SENDER = address(0x5EEDED);

    function setUp() public {
        nm = new NonceManager(address(this));
    }

    function _keys(uint256 n, uint256 seed) internal pure returns (bytes32[] memory out) {
        out = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) out[i] = keccak256(abi.encode(seed, i));
    }

    function test_set_consumed_at_shared_seq() public {
        bytes32[] memory k = _keys(2, 1);
        nm.consumeFreshMany(SENDER, k);
        require(nm.current(SENDER, k[0]) == 1 && nm.current(SENDER, k[1]) == 1, "set consumed");
    }

    function test_disjoint_sets_are_replay_independent() public {
        nm.consumeFreshMany(SENDER, _keys(2, 1));
        nm.consumeFreshMany(SENDER, _keys(2, 2)); // must not interfere
    }

    function test_duplicate_key_in_one_set_reverts() public {
        bytes32[] memory k = _keys(2, 1);
        k[1] = k[0];
        vm.expectRevert(NonceManager.NonceKeyAlreadyUsed.selector);
        nm.consumeFreshMany(SENDER, k);
    }

    /// The load-bearing atomicity property: a set overlapping one used key
    /// consumes NOTHING, so a refused multi-input spend cannot half-burn.
    function test_overlapping_set_consumes_nothing() public {
        bytes32[] memory first = _keys(1, 1);
        nm.consumeFreshMany(SENDER, first);
        bytes32[] memory second = new bytes32[](2);
        second[0] = keccak256(abi.encode(uint256(9), uint256(0))); // fresh
        second[1] = first[0];                                      // used
        vm.expectRevert(NonceManager.NonceKeyAlreadyUsed.selector);
        nm.consumeFreshMany(SENDER, second);
        require(nm.current(SENDER, second[0]) == 0, "fresh key must stay fresh");
    }

    function test_per_sender_domains() public {
        bytes32[] memory k = _keys(2, 1);
        nm.consumeFreshMany(SENDER, k);
        // the same set under another sender is fresh (why the pool pins one)
        require(nm.current(address(0xEEEE), k[0]) == 0, "per-sender domain");
        nm.consumeFreshMany(address(0xEEEE), k);
    }

    function test_zero_key_reverts() public {
        bytes32[] memory k = _keys(2, 1);
        k[1] = bytes32(0);
        vm.expectRevert(NonceManager.ZeroNonceKey.selector);
        nm.consumeFreshMany(SENDER, k);
    }

    function test_empty_set_reverts() public {
        vm.expectRevert(NonceManager.EmptyKeySet.selector);
        nm.consumeFreshMany(SENDER, new bytes32[](0));
    }

    function test_more_than_max_keys_reverts() public {
        vm.expectRevert(NonceManager.TooManyKeys.selector);
        nm.consumeFreshMany(SENDER, _keys(17, 1));
    }

    function test_only_pool_may_consume() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(NonceManager.NotPool.selector);
        nm.consumeFreshMany(SENDER, _keys(1, 1));
    }
}
