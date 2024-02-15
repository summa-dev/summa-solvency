// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "./interfaces/IVerifier.sol";

contract Summa is Ownable {
    /**
     * @dev Struct representing the configuration of the Summa instance
     * @param cryptocurrencyNames The names of the cryptocurrencies whose balances are encoded in the polynomials
     * @param cryptocurrencyChains The chains of the cryptocurrencies whose balances are encoded in the polynomials
     * @param balanceByteRange The number of bytes used to represent the balance of a cryptocurrency in the polynomials
     */
    struct SummaConfig {
        string[] cryptocurrencyNames;
        string[] cryptocurrencyChains;
        uint8 balanceByteRange;
    }
    /**
     * @dev Struct representing an address ownership proof submitted by the CEX
     * @param cexAddress The address owned by the CEX (submitted as a string, as it can be a non-EVM address)
     * @param chain The name of the chain name where the address belongs (e.g., ETH, BTC)
     * @param signature The signature of the message signed by the address public key
     * @param message The message signed by the address public key
     */
    struct AddressOwnershipProof {
        string cexAddress;
        string chain;
        bytes signature;
        bytes message;
    }

    // Summa configuration
    SummaConfig public config;

    // Verification key contract address
    address public immutable verificationKey;

    // List of all address ownership proofs submitted by the CEX
    AddressOwnershipProof[] public addressOwnershipProofs;

    // Liabilities commitments by timestamp submitted by the CEX
    mapping(uint256 => bytes) public commitments;

    // Convenience mapping to check if an address has already been verified
    mapping(bytes32 => uint256) private _ownershipProofByAddress;

    // zkSNARK verifier of the valid polynomial encoding
    IVerifier private immutable polynomialEncodingVerifier;

    event AddressOwnershipProofSubmitted(
        AddressOwnershipProof[] addressOwnershipProofs
    );
    event LiabilitiesCommitmentSubmitted(
        uint256 indexed timestamp,
        bytes proof
    );

    constructor(
        address _verificationKey,
        IVerifier _polynomialEncodingVerifier,
        string[] memory cryptocurrencyNames,
        string[] memory cryptocurrencyChains,
        uint8 balanceByteRange
    ) {
        require(
            _verificationKey != address(0),
            "Invalid verifying key address"
        );
        verificationKey = _verificationKey;
        require(
            cryptocurrencyNames.length == cryptocurrencyChains.length,
            "Cryptocurrency names and chains number mismatch"
        );
        for (uint i = 0; i < cryptocurrencyNames.length; i++) {
            require(
                bytes(cryptocurrencyNames[i]).length != 0 &&
                    bytes(cryptocurrencyChains[i]).length != 0,
                "Invalid cryptocurrency"
            );
        }
        require(
            validateVKPermutationsLength(
                _verificationKey,
                cryptocurrencyNames.length
            ),
            "The number of cryptocurrencies does not correspond to the verifying key"
        );
        require(
            address(_polynomialEncodingVerifier) != address(0),
            "Invalid polynomial encoding verifier address"
        );
        polynomialEncodingVerifier = _polynomialEncodingVerifier;
        require(balanceByteRange > 0, "Invalid balance byte range");
        config = SummaConfig(
            cryptocurrencyNames,
            cryptocurrencyChains,
            balanceByteRange
        );
    }

    /**
     * @dev Validate the number of permutations in the verifying key
     * @param vkContract The address of the verifying key contract
     * @param numberOfCurrencies The number of cryptocurrencies whose polynomials are committed in the proof
     * @return isValid True if the number of permutations in the verifying key corresponds to the number of cryptocurrencies
     */
    function validateVKPermutationsLength(
        address vkContract,
        uint256 numberOfCurrencies
    ) internal view returns (bool isValid) {
        // The number of permutations is 2 + 4 * numberOfCurrencies because of the circuit structure:
        // 1 per instance column, 1 per constant column (range check) and 4 per range check columns times the number of currencies
        uint256 numPermutations = 2 + 4 * numberOfCurrencies;

        uint256 startOffsetForPermutations = 0x2e0; // The value can be observed in the VerificationKey contract, the offset is pointing after all the parameters and the fixed column commitment

        // The offset after the last permutation is the start offset plus the number of permutations times 0x40 (the size of a permutation)
        uint256 offsetAfterLastPermutation = startOffsetForPermutations +
            numPermutations *
            0x40;

        // extcodecopy is a gas-expensive operation per byte, so we want to minimize the number of bytes we read.
        // This hack is to read the 32 (0x20) bytes that overlap the last permutation and the empty memory location behind it.
        // For example, a circuit with 2 currencies will have 10 permutations, so the location behind the last permutation will be at 0x2e0 + 10 * 0x40 = 0x0560
        // We read 0x20 bytes starting from 0x0550, which will include a piece of the last permutation and the empty memory location behind it.
        uint256 readOffset = offsetAfterLastPermutation - 0x10;
        bool valid;
        // Extract the last permutation
        assembly {
            // Read the memory location into 0x00
            extcodecopy(vkContract, 0x00, readOffset, 0x20)
            // Load the read bytes from 0x00 into a variable
            let readBytes := mload(0x00)
            // We expect the left 16 bytes to be nonzero and the right 16 bytes to be zero
            valid := and(not(iszero(readBytes)), iszero(and(readBytes, 0x0f)))
        }
        return valid;
    }

    function getAddressOwnershipProof(
        bytes32 addressHash
    ) public view returns (AddressOwnershipProof memory) {
        require(
            _ownershipProofByAddress[addressHash] > 0,
            "Address not verified"
        );
        // -1 comes from the fact that 0 is reserved to distinguish the case when the proof has not yet been submitted
        return
            addressOwnershipProofs[_ownershipProofByAddress[addressHash] - 1];
    }

    /**
     * @dev Submit an optimistic proof of multiple address ownership for a CEX. The proof is subject to an off-chain verification as it's not feasible to verify the signatures of non-EVM chains in an Ethereum smart contract.
     * @param _addressOwnershipProofs The list of address ownership proofs
     */
    function submitProofOfAddressOwnership(
        AddressOwnershipProof[] memory _addressOwnershipProofs
    ) public onlyOwner {
        for (uint i = 0; i < _addressOwnershipProofs.length; i++) {
            bytes32 addressHash = keccak256(
                abi.encodePacked(_addressOwnershipProofs[i].cexAddress)
            );
            uint256 proofIndex = _ownershipProofByAddress[addressHash];
            require(proofIndex == 0, "Address already verified");

            addressOwnershipProofs.push(_addressOwnershipProofs[i]);
            _ownershipProofByAddress[addressHash] = addressOwnershipProofs
                .length;
            require(
                bytes(_addressOwnershipProofs[i].cexAddress).length != 0 &&
                    bytes(_addressOwnershipProofs[i].chain).length != 0 &&
                    _addressOwnershipProofs[i].signature.length != 0 &&
                    _addressOwnershipProofs[i].message.length != 0,
                "Invalid proof of address ownership"
            );
        }

        emit AddressOwnershipProofSubmitted(_addressOwnershipProofs);
    }

    /**
     * @dev Submit commitment for a CEX
     * @param proof ZK proof of the valid polynomial encoding
     * @param timestamp The timestamp at which the CEX took the snapshot of its assets and liabilities
     */
    function submitCommitment(
        bytes memory proof,
        uint256 timestamp
    ) public onlyOwner {
        require(proof.length == 5376, "Invalid proof length");
        uint[] memory args = new uint[](1);
        args[0] = 1; // Workaround to satisfy the verifier (TODO remove after https://github.com/summa-dev/halo2-solidity-verifier/issues/1 is resolved)
        require(
            polynomialEncodingVerifier.verifyProof(
                verificationKey,
                proof,
                args
            ),
            "Invalid proof"
        );
        // TODO slice the proof to get the ID and balance commitments
        // require(
        //     balanceCommitments.length == config.cryptocurrencies.length,
        //     "Liability commitments and cryptocurrencies number mismatch"
        // );

        commitments[timestamp] = proof;

        emit LiabilitiesCommitmentSubmitted(timestamp, proof);
    }
}
