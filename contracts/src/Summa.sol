// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "./interfaces/IVerifier.sol";

contract Summa is Ownable {
    /**
     * @dev Struct representing the configuration of the Summa instance
     * @param currenciesCount The number of cryptocurrency balances encoded in the polynomials
     * @param balanceByteRange The number of bytes used to represent the balance of a cryptocurrency in the polynomials
     */
    struct SummaConfig {
        uint16 currenciesCount;
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

    /**
     * @dev Struct identifying a cryptocurrency traded on the CEX
     * @param name The name of the cryptocurrency
     * @param chain The name of the chain name where the cryptocurrency lives (e.g., ETH, BTC)
     */
    struct Cryptocurrency {
        string name;
        string chain;
    }

    /**
     * @dev Struct representing a commitment submitted by the CEX.
     * @param proof ZK proof of the valid polynomial encoding
     * @param blockchainNames The names of the blockchains where the CEX holds the cryptocurrencies included into the balance polynomials
     * @param cryptocurrencyNames The names of the cryptocurrencies included into the balance polynomials
     */
    struct Commitment {
        bytes proof;
        string[] cryptocurrencyNames;
        string[] blockchainNames;
    }

    // Summa configuration
    SummaConfig public config;

    // Verification key contract address
    address public verificationKey;

    // List of all address ownership proofs submitted by the CEX
    AddressOwnershipProof[] public addressOwnershipProofs;

    // Solvency commitments by timestamp submitted by the CEX
    mapping(uint256 => Commitment) public commitments;

    // Convenience mapping to check if an address has already been verified
    mapping(bytes32 => uint256) private _ownershipProofByAddress;

    // zkSNARK verifier of the valid polynomial encoding
    IVerifier private immutable polynomialEncodingVerifier;

    event AddressOwnershipProofSubmitted(
        AddressOwnershipProof[] addressOwnershipProofs
    );
    event LiabilitiesCommitmentSubmitted(
        uint256 indexed timestamp,
        bytes proof,
        Cryptocurrency[] cryptocurrencies
    );

    constructor(
        address _verificationKey,
        IVerifier _polynomialEncodingVerifier,
        uint16 currenciesCount,
        uint8 balanceByteRange
    ) {
        require(
            _verificationKey != address(0),
            "Invalid verifying key address"
        );
        verificationKey = _verificationKey;
        require(
            address(_polynomialEncodingVerifier) != address(0),
            "Invalid polynomial encoding verifier address"
        );
        polynomialEncodingVerifier = _polynomialEncodingVerifier;
        config = SummaConfig(currenciesCount, balanceByteRange);
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
     * @param cryptocurrencies The cryptocurrencies included into the balance polynomials
     * @param timestamp The timestamp at which the CEX took the snapshot of its assets and liabilities
     */
    function submitCommitment(
        bytes memory proof,
        Cryptocurrency[] memory cryptocurrencies,
        uint256 timestamp
    ) public onlyOwner {
        require(proof.length == 5376, "Invalid proof length");
        require(
            cryptocurrencies.length > 0,
            "Cryptocurrencies list cannot be empty"
        );
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
        // TODO slice the proof to get the balance commitments
        // require(
        //     balanceCommitments.length == cryptocurrencies.length,
        //     "Liability commitments and cryptocurrencies number mismatch"
        // );

        string[] memory cryptocurrencyNames = new string[](
            cryptocurrencies.length
        );
        string[] memory blockchainNames = new string[](cryptocurrencies.length);
        for (uint i = 0; i < cryptocurrencies.length; i++) {
            require(
                bytes(cryptocurrencies[i].chain).length != 0 &&
                    bytes(cryptocurrencies[i].name).length != 0,
                "Invalid cryptocurrency"
            );
            cryptocurrencyNames[i] = cryptocurrencies[i].name;
            blockchainNames[i] = cryptocurrencies[i].chain;
        }

        commitments[timestamp] = Commitment(
            proof,
            cryptocurrencyNames,
            blockchainNames
        );

        emit LiabilitiesCommitmentSubmitted(timestamp, proof, cryptocurrencies);
    }
}
