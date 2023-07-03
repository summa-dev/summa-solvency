// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface Verifier {
    function verify(
        uint256[] calldata pubInputs,
        bytes calldata proof
    ) external view returns (bool);
}

contract Summa is Ownable {
    using ECDSA for bytes32;

    uint256 constant ETH_INPUTS = 1;
    uint256 constant ERC20_INPUTS = 1;

    struct PublicInput {
        string exchangeId;
        address[] cexETHAddresses;
        address[] cexERC20Addresses;
        uint256[] cexETHBalances;
        uint256[] cexERC20Balances;
        address[] erc20ContractAddresses;
        bytes[] cexEthAddressSignatures;
        bytes[] cexERC20AddressSignatures;
        uint256 mstRoot;
    }

    Verifier private verifier;

    event ProofOfSolvencySubmitted(bytes32 indexed exchangeId);

    constructor(Verifier _verifier) {
        verifier = _verifier;
    }

    function submitProofOfSolvency(
        PublicInput memory publicInput,
        bytes memory proof
    ) public {
        require(
            publicInput.cexEthAddressSignatures.length == ETH_INPUTS &&
                publicInput.cexETHAddresses.length == ETH_INPUTS &&
                publicInput.cexETHBalances.length == ETH_INPUTS,
            "CEX ETH addresses, balances, and signatures count mismatch"
        );

        require(
            publicInput.cexERC20AddressSignatures.length == ERC20_INPUTS &&
                publicInput.cexERC20Addresses.length == ERC20_INPUTS &&
                publicInput.erc20ContractAddresses.length == ERC20_INPUTS &&
                publicInput.cexERC20Balances.length == ERC20_INPUTS,
            "CEX ERC20 addresses, balances, and signatures count mismatch"
        );

        for (uint i = 0; i < publicInput.cexEthAddressSignatures.length; i++) {
            // Check that message is "summa proof of solvency {exchangeId}" and the signature is valid
            address recoveredPubKey = keccak256(
                abi.encode(
                    "Summa proof of solvency for ",
                    publicInput.exchangeId
                )
            ).toEthSignedMessageHash().recover(
                    publicInput.cexEthAddressSignatures[i]
                );
            require(
                publicInput.cexETHAddresses[i] == recoveredPubKey,
                "Invalid signer for ETH address"
            );
            require(
                publicInput.cexETHBalances[i] <=
                    publicInput.cexETHAddresses[i].balance,
                "Actual ETH balance less than the proven balance"
            );
        }

        for (
            uint i = 0;
            i < publicInput.cexERC20AddressSignatures.length;
            i++
        ) {
            address recoveredPubKey = keccak256(
                abi.encode(
                    "Summa proof of solvency for ",
                    publicInput.exchangeId
                )
            ).toEthSignedMessageHash().recover(
                    publicInput.cexERC20AddressSignatures[i]
                );
            require(
                publicInput.cexERC20Addresses[i] == recoveredPubKey,
                "Invalid signer for ERC20 address"
            );
            require(
                publicInput.cexERC20Balances[i] <=
                    IERC20(publicInput.erc20ContractAddresses[i]).balanceOf(
                        publicInput.cexERC20Addresses[i]
                    ),
                "Actual ERC20 balance less than the proven balance"
            );
        }

        // Verify ZK proof
        uint256[] memory inputs = new uint256[](ETH_INPUTS + ERC20_INPUTS + 1);
        inputs[0] = publicInput.mstRoot;

        for (uint i = 0; i < ETH_INPUTS; i++) {
            inputs[i + 1] = publicInput.cexETHBalances[i];
        }

        for (uint i = 0; i < ERC20_INPUTS; i++) {
            inputs[i + ETH_INPUTS + 1] = publicInput.cexERC20Balances[i];
        }

        require(verifyZkProof(proof, inputs), "Invalid zk proof");

        emit ProofOfSolvencySubmitted(
            keccak256(abi.encode(publicInput.exchangeId))
        );
    }

    function verifyZkProof(
        bytes memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        return verifier.verify(publicInputs, proof);
    }
}
