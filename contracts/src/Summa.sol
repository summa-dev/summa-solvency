// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";

import "./interfaces/IVerifier.sol";

contract Summa is Ownable {
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
     * @dev Struct representing an asset owned by the CEX
     * @param assetName The name of the asset
     * @param chain The name of the chain name where the asset lives (e.g., ETH, BTC)
     */
    struct Asset {
        string assetName;
        string chain;
    }

    /**
     * @dev Struct representing a commitment submitted by the CEX.
     * @param mstRoot Merkle sum tree root of the CEX's liabilities
     * @param rootBalances The total sums of the assets included in the tree
     * @param assetChains The chains where the CEX holds the assets included into the tree
     * @param assetNames The names of the assets included into the tree
     */
    struct Commitment {
        uint256 mstRoot;
        uint256[] rootBalances;
        string[] assetNames;
        string[] assetChains;
    }

    // User inclusion proof verifier
    IVerifier private immutable inclusionVerifier;

    // List of all address ownership proofs submitted by the CEX
    AddressOwnershipProof[] public addressOwnershipProofs;

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

    // Convenience mapping to check if an address has already been verified
    mapping(bytes32 => uint256) private _ownershipProofByAddress;

    // Solvency commitments by timestamp submitted by the CEX
    mapping(uint256 => Commitment) public commitments;

    event AddressOwnershipProofSubmitted(
        AddressOwnershipProof[] addressOwnershipProofs
    );
    event LiabilitiesCommitmentSubmitted(
        uint256 indexed timestamp,
        uint256 mstRoot,
        uint256[] rootBalances,
        Asset[] assets
    );

    constructor(IVerifier _inclusionVerifier) {
        inclusionVerifier = _inclusionVerifier;
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
     * @dev Submit proof of solvency for a CEX
     * @param mstRoot Merkle sum tree root of the CEX's liabilities
     * @param rootBalances The total sums of the assets included into the Merkle sum tree
     * @param assets The assets included into the Merkle sum tree
     * @param timestamp The timestamp at which the CEX took the snapshot of its assets and liabilities
     */
    function submitCommitment(
        uint256 mstRoot,
        uint256[] memory rootBalances,
        Asset[] memory assets,
        uint256 timestamp
    ) public onlyOwner {
        require(mstRoot != 0, "Invalid MST root");
        require(
            rootBalances.length == assets.length,
            "Root asset sums and asset number mismatch"
        );
        string[] memory assetNames = new string[](assets.length);
        string[] memory assetChains = new string[](assets.length);
        for (uint i = 0; i < assets.length; i++) {
            require(
                bytes(assets[i].chain).length != 0 &&
                    bytes(assets[i].assetName).length != 0,
                "Invalid asset"
            );
            require(
                rootBalances[i] != 0,
                "All root sums should be greater than zero"
            );
            assetNames[i] = assets[i].assetName;
            assetChains[i] = assets[i].chain;
        }

        commitments[timestamp] = Commitment(
            mstRoot,
            rootBalances,
            assetNames,
            assetChains
        );

        emit LiabilitiesCommitmentSubmitted(
            timestamp,
            mstRoot,
            rootBalances,
            assets
        );
    }

    /**
     * Verify the proof of user inclusion into the liabilities tree
     * @param proof ZK proof
     * @param publicInputs proof inputs
     */
    function verifyInclusionProof(
        bytes memory proof,
        uint256[] memory publicInputs,
        uint256 timestamp
    ) public view returns (bool) {
        require(
            commitments[timestamp].mstRoot == publicInputs[1],
            "Invalid MST root"
        );
        for (uint i = 2; i < publicInputs.length; i++) {
            require(
                commitments[timestamp].rootBalances[i - 2] == publicInputs[i],
                "Invalid root balance"
            );
        }
        return inclusionVerifier.verify(publicInputs, proof);
    }
}
