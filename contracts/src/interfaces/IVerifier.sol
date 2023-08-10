// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

/**
 * @dev Zero-knowledge proof verifier
 */
interface IVerifier {
    /**
     * @dev Verify a proof
     * @param pubInputs The public inputs to the proof
     * @param proof The proof
     * @return true if the proof is valid, false otherwise
     */
    function verify(
        uint256[] calldata pubInputs,
        bytes calldata proof
    ) external view returns (bool);
}
