// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev Inclusion proof verifier
 */
interface IInclusionVerifier {
    /**
     * @dev Verify a proof
     * @param vk The verification key
     * @param proof The proof
     * @param challenges The pre-calculated g2 points with challenge
     * @param values The user data that includes userId, balance of currency
     * @return true if the proof is valid, false otherwise
     */
        function verifyProof(
        address vk,
        bytes calldata proof,
        uint256[] calldata challenges,
        uint256[] calldata values
    ) external view returns (bool);
}
