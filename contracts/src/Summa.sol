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

    Verifier private verifier;

    event ProofOfSolvencySubmitted(bytes32 indexed exchangeId);

    constructor(Verifier _verifier) {
        verifier = _verifier;
    }

    function submitProofOfSolvency(
        string memory exchangeId,
        address[] memory cexETHAddresses,
        address[] memory cexERC20Addresses,
        uint256[] memory cexETHBalances,
        uint256[] memory cexERC20Balances,
        address[] memory erc20ContractAddresses,
        bytes[] memory cexEthAddressSignatures,
        bytes[] memory cexERC20AddressSignatures,
        uint256 mstRoot,
        bytes memory proof
    ) public {
        require(
            cexEthAddressSignatures.length == ETH_INPUTS &&
                cexETHAddresses.length == ETH_INPUTS &&
                cexETHBalances.length == ETH_INPUTS,
            "CEX ETH addresses, balances, and signatures count mismatch"
        );

        require(
            cexERC20AddressSignatures.length == ERC20_INPUTS &&
            cexERC20Addresses.length == ERC20_INPUTS &&
            erc20ContractAddresses.length == ERC20_INPUTS &&
            cexERC20Balances.length == ERC20_INPUTS,
            "CEX ERC20 addresses, balances, and signatures count mismatch"
        );

        for (uint i = 0; i < cexEthAddressSignatures.length; i++) {
            // Check that message is "summa proof of solvency {exchangeId}" and the signature is valid
            address recoveredPubKey = keccak256(
                abi.encode(
                    "Summa proof of solvency for ",
                    exchangeId
                )
            ).toEthSignedMessageHash().recover(
                    cexEthAddressSignatures[i]
                );
            require(
                cexETHAddresses[i] == recoveredPubKey,
                "Invalid signer for ETH address"
            );
            require(
                cexETHBalances[i] <=
                    cexETHAddresses[i].balance,
                "Actual ETH balance less than the proven balance"
            );
        }

        for (
            uint i = 0;
            i < cexERC20AddressSignatures.length;
            i++
        ) {
            address recoveredPubKey = keccak256(
                abi.encode(
                    "Summa proof of solvency for ",
                    exchangeId
                )
            ).toEthSignedMessageHash().recover(
                    cexERC20AddressSignatures[i]
                );
            require(
                cexERC20Addresses[i] == recoveredPubKey,
                "Invalid signer for ERC20 address"
            );
            require(
                cexERC20Balances[i] <=
                    IERC20(erc20ContractAddresses[i]).balanceOf(
                        cexERC20Addresses[i]
                    ),
                "Actual ERC20 balance less than the proven balance"
            );
        }

        // Verify ZK proof
        uint256[] memory inputs = new uint256[](ETH_INPUTS + ERC20_INPUTS + 1);
        inputs[0] = mstRoot;

        for (uint i = 0; i < ETH_INPUTS; i++) {
            inputs[i + 1] = cexETHBalances[i];
        }

        for (uint i = 0; i < ERC20_INPUTS; i++) {
            inputs[i + ETH_INPUTS + 1] = cexERC20Balances[i];
        }

        require(verifyZkProof(proof, inputs), "Invalid zk proof");

        emit ProofOfSolvencySubmitted(
            keccak256(abi.encode(exchangeId))
        );
    }

    function verifyZkProof(
        bytes memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        return verifier.verify(publicInputs, proof);
    }
}
