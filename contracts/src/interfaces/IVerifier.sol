// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev Zk-SNARK and grand sum proof proof verifier
 */
interface IVerifier {
    /**
     * @dev Verify a proof
     * @param vk The verification key
     * @param proof The proof
     * @param instances The public inputs to the proof
     * @return true if the proof is valid, false otherwise
     */
    function verifyProof(
        address vk,
        bytes calldata proof,
        uint256[] calldata instances
    ) external view returns (bool);
}
