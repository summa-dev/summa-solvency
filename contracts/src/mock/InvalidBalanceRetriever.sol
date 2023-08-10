// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import "./../interfaces/IBalanceRetriever.sol";

contract InvalidBalanceRetriever is IBalanceRetriever {
    function getAddressBalance(
        bytes memory __,
        bytes memory ___,
        uint256 ____
    ) external pure override returns (uint256) {
        return 0;
    }

    function getAssetType() external pure override returns (bytes32) {
        return 0;
    }
}
