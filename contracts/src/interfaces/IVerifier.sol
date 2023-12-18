// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev Zero-knowledge proof verifier
 */
interface IVerifier {
    /**
     * @dev Verify a proof
     * @param proof The proof
     * @param instances The public inputs to the proof
     * @return true if the proof is valid, false otherwise
     */
    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) external view returns (bool);
}
