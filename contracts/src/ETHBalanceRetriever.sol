// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import "./interfaces/IBalanceRetriever.sol";

contract ETHBalanceRetriever is IBalanceRetriever {
    /**
     * Gets the ETH balance of an address
     * @param _address CEX address that holds ETH
     * @param args not used for ETH
     * @param timestamp is reserved for future use
     */
    function getAddressBalance(
        bytes memory _address,
        bytes memory args,
        uint256 timestamp
    ) external view override returns (uint256) {
        return abi.decode(_address, (address)).balance;
    }

    function getAssetType() external pure override returns (bytes32) {
        return keccak256("ETH");
    }
}
