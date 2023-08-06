// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import "./interfaces/IVerifier.sol";
import "./interfaces/IBalanceRetriever.sol";
import "./interfaces/IAddressOwnershipVerifier.sol";

contract Summa is Ownable {
    using ECDSA for bytes32;

    IVerifier private immutable verifier;

    mapping(bytes32 => bool) public confirmedAddress; // instead ofbool, should contain the additional data needed to verify the address ownership (e.g., in case of ERC20, the address of the ERC20 contract)

    mapping(bytes32 => IBalanceRetriever) public balanceRetriever;
    mapping(bytes32 => bytes) public balanceRetrieverArgs;
    mapping(bytes32 => IAddressOwnershipVerifier) public cexAddressVerifier;

    /**
     * @dev Struct representing an address owned by the CEX
     * @param addressType The type of the address by chain (e.g., EVM, BTC)
     * @param cexAddress The address owned by the CEX
     * @param ownershipProof The data needed to verify the address ownership (e.g., in case of EVM, a signature and a message signed by the address, encoded as bytes)
     */
    struct OwnedAddress {
        bytes32 addressType;
        bytes cexAddress;
        bytes ownershipProof;
    }

    /**
     * @dev Struct representing an asset owned by the CEX
     * @param assetType The type of the asset (e.g., a hash of the asset kind, like keccak256("ETH"), keccak256("BTC", keccak256("ERC20")
     * @param amountToProve The amount of the asset that the CEX wants to prove to own
     * @param addresses The addresses that the CEX wants to prove to own the asset
     * @param balanceRetrieverArgs Additional arguments needed to get the balance (e.g., in case of ERC20, the address of the ERC20 contract)
     */
    struct OwnedAsset {
        bytes32 assetType;
        uint256 amountToProve;
        bytes[] addresses;
        bytes balanceRetrieverArgs;
    }

    event AddressVerifierSet(bytes32 indexed addressType, address verifier);
    event BalanceRetrieverSet(
        bytes32 indexed assetType,
        address balanceRetriever
    );
    event ExchangeAddressesSubmitted(OwnedAddress[] addresses);
    event ProofOfSolvencySubmitted(uint256 indexed mstRoot);

    constructor(IVerifier _verifier) {
        verifier = _verifier;
    }

    /**
     * @dev Set the address of the asset balance retriever for a given asset type
     * @param retriever The address of the asset balance retriever smart contract
     */
    function setBalanceRetriever(address retriever) public onlyOwner {
        require(retriever != address(0), "Invalid balance retriever");
        IBalanceRetriever _balanceRetriever = IBalanceRetriever(retriever);
        bytes32 assetType = _balanceRetriever.getAssetType();
        require(assetType != bytes32(0), "Invalid asset type");
        balanceRetriever[assetType] = _balanceRetriever;
        emit BalanceRetrieverSet(assetType, retriever);
    }

    /**
     * @dev Set the address of the address ownership verifier for a given asset type
     * @param _verifier The address of the address ownership verifier smart contract
     */
    function setAssetAddressVerifier(address _verifier) public onlyOwner {
        require(_verifier != address(0), "Invalid address verifier");
        IAddressOwnershipVerifier addressOwnershipVerifier = IAddressOwnershipVerifier(
                _verifier
            );
        bytes32 addressType = addressOwnershipVerifier.getAddressType();
        require(addressType != bytes32(0), "Invalid address type");
        cexAddressVerifier[addressType] = addressOwnershipVerifier;
        emit AddressVerifierSet(addressType, _verifier);
    }

    function submitProofOfAccountOwnership(
        OwnedAddress[] memory _cexAddresses
    ) public {
        for (uint i = 0; i < _cexAddresses.length; i++) {
            bytes32 addressHash = keccak256(_cexAddresses[i].cexAddress);
            require(!confirmedAddress[addressHash], "Address already verified");
            confirmedAddress[addressHash] = true;
            require(
                address(cexAddressVerifier[_cexAddresses[i].addressType]) !=
                    address(0),
                "Address verifier not set for this type of address"
            );
            require(
                cexAddressVerifier[_cexAddresses[i].addressType]
                    .verifyAddressOwnership(
                        _cexAddresses[i].cexAddress,
                        _cexAddresses[i].ownershipProof
                    ),
                "Invalid signer"
            );
        }

        emit ExchangeAddressesSubmitted(_cexAddresses);
    }

    /**
     * @dev Submit proof of solvency for a CEX
     * @param assets Assets owned by CEX
     * @param mstRoot The root of the Merkle sum tree
     * @param proof The ZK proof
     * @param timestamp The timestamp at which the proof was generated
     */
    function submitProofOfSolvency(
        OwnedAsset[] memory assets,
        uint256 mstRoot,
        bytes memory proof,
        uint256 timestamp
    ) public {
        uint256[] memory totalAssetSum = new uint256[](assets.length);

        for (uint i = 0; i < assets.length; i++) {
            for (uint j = 0; j < assets[i].addresses.length; j++) {
                require(
                    confirmedAddress[keccak256(assets[i].addresses[j])],
                    "Address ownership not verified"
                );
                require(
                    balanceRetriever[assets[i].assetType] !=
                        IBalanceRetriever(address(0)),
                    "Balance retriever not set for this type of asset"
                );
                totalAssetSum[i] += balanceRetriever[assets[i].assetType]
                    .getAddressBalance(
                        assets[i].addresses[j],
                        assets[i].balanceRetrieverArgs,
                        timestamp
                    );
            }
            require(
                assets[i].amountToProve <= totalAssetSum[i],
                "Actual balance is less than the proven balance"
            );
        }

        uint256[] memory inputs = new uint256[](assets.length + 1);
        inputs[0] = mstRoot;

        for (uint i = 0; i < assets.length; i++) {
            inputs[i + 1] = assets[i].amountToProve;
        }

        // Verify ZK proof
        require(verifyZkProof(proof, inputs), "Invalid zk proof");

        emit ProofOfSolvencySubmitted(mstRoot);
    }

    function verifyZkProof(
        bytes memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        return verifier.verify(publicInputs, proof);
    }
}
