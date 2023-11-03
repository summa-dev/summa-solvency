// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

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
     * @param amount The total amount of the asset that the CEX holds on a given chain
     */
    struct Asset {
        string assetName;
        string chain;
        uint256 amount;
    }

    /**
     * @dev Struct representing a commitment submitted by the CEX
     * @param mstRoot Merkle sum tree root of the CEX's liabilities
     * @param rootSum The total sum of the tree asset
     */
    struct Commitment {
        uint256 mstRoot;
        uint256 rootSum;
        Asset asset;
    }

    //User inclusion proof verifier
    IVerifier private immutable inclusionVerifier;

    // All address ownership proofs submitted by the CEX
    AddressOwnershipProof[] public addressOwnershipProofs;

    // Convenience mapping to check if an address has already been verified
    /*
     Boolean type is better than uint256 for this mapping, at least more than 2,100 gas is saved per call
    */
    mapping(bytes32 => uint256) public ownershipProofByAddress;

    // Solvency commitments by timestamp submitted by the CEX
    mapping(uint256 => Commitment) public commitments;

    event AddressOwnershipProofSubmitted(
        AddressOwnershipProof[] addressOwnershipProofs
    );
    event SolvencyProofSubmitted(
        uint256 indexed timestamp,
        uint256 mstRoot,
        uint256 rootSum,
        Asset assets
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
                abi.encode(_addressOwnershipProofs[i].cexAddress)
            );
            uint256 index = ownershipProofByAddress[addressHash];
            require(index == 0, "Address already verified");
            //Offsetting the index by 1 to distinguish with the case when the proof hasn't been submitted (the storage slot would be zero)
            ownershipProofByAddress[addressHash] = i + 1;
            addressOwnershipProofs.push(_addressOwnershipProofs[i]);
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
     * @param rootSum The total sum of the given asset across all the CEX liabilities
     * @param asset The assets owned by the CEX
     * @param timestamp The timestamp at which the CEX took the snapshot of its assets and liabilities
     */
    function submitCommitment(
        uint256 mstRoot,
        uint256 rootSum,
        Asset memory asset,
        uint256 timestamp
    ) public onlyOwner {
        require(
            addressOwnershipProofs.length != 0,
            "The CEX has not submitted any address ownership proofs"
        );

        require(
            bytes(asset.chain).length != 0 &&
                bytes(asset.assetName).length != 0,
            "Invalid asset"
        );
        require(rootSum != 0, "Root sum should be greater than zero");

        commitments[timestamp] = Commitment(mstRoot, rootSum, asset);

        emit SolvencyProofSubmitted(timestamp, mstRoot, rootSum, asset);
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
        return inclusionVerifier.verify(publicInputs, proof);
    }
}
