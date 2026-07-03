// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {PoseidonT3} from "./PoseidonT3.sol";
import {PoseidonT4} from "./PoseidonT4.sol";

/// @title PoseidonBN254 — circomlib's Poseidon, on-chain
/// @notice Facade over PoseidonT3/PoseidonT4 (see those files for the round
///         function). Split so each half deploys under the hegota devnet's
///         2^24 per-tx gas cap; callers and the differential vector tests are
///         unchanged. Inline wrappers compile to one DELEGATECALL per hash,
///         exactly as the pre-split public library did.
library PoseidonBN254 {
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function hash2(uint256 x0, uint256 x1) internal pure returns (uint256) {
        return PoseidonT3.hash2(x0, x1);
    }

    function hash3(uint256 x0, uint256 x1, uint256 x2) internal pure returns (uint256) {
        return PoseidonT4.hash3(x0, x1, x2);
    }
}
