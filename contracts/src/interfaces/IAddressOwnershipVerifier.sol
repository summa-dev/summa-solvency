// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev Interface for address ownership verifier contracts
 */
interface IAddressOwnershipVerifier {
    /**
     * @dev Verify the ownership of an address.
     * @param cexAddress The address to verify (e.g., in case of ETH, the ETH address)
     * @param addressOwnershipProof The data needed to verify the address ownership (e.g., in case of ETH, a signature and a message signed by the address, encoded as bytes)
     */
    function verifyAddressOwnership(
        bytes memory cexAddress,
        bytes memory addressOwnershipProof
    ) external view returns (bool);
}
