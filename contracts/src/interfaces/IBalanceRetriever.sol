// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev Interface for asset balance retriever contracts
 */
interface IBalanceRetriever {
    /**
     * @dev Get the asset type (e.g., ETH, ERC20, etc.)
     */
    function getAssetType() external view returns (bytes32);

    /**
     * @dev Get the balance of an address for a given asset type. Gets address balance for ETH, balanceOf() for ERC20, or calls an oracle for non-native assets
     * @param _address The address to check the balance of
     * @param args Additional arguments needed to get the balance (e.g., in case of ERC20, the address of the ERC20 contract)
     * @param timestamp The timestamp at which the balance should be queried
     * @return The balance of the address for the given asset type
     */
    function getAddressBalance(
        bytes memory _address,
        bytes memory args,
        uint256 timestamp
    ) external view returns (uint256);
}
