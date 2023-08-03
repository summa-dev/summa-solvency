// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import "./interfaces/IBalanceRetriever.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract ERC20BalanceRetriever is IBalanceRetriever {
    /**
     * Gets the balance of an address for a given ERC20 token
     * @param _address CEX address that holds the ERC20 token
     * @param args should contain the address of the ERC20 contract encoded as bytes
     * @param timestamp is reserved for future use
     */
    function getAddressBalance(
        bytes memory _address,
        bytes memory args,
        uint256 timestamp
    ) external view override returns (uint256) {
        address erc20Address = abi.decode(args, (address));
        return IERC20(erc20Address).balanceOf(abi.decode(_address, (address)));
    }

    function getAssetType() external pure override returns (bytes32) {
        return keccak256("ERC20");
    }
}
