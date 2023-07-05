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

    Verifier private verifier;

    event ProofOfSolvencySubmitted(bytes32 indexed exchangeId, uint256 mstRoot);

    constructor(Verifier _verifier) {
        verifier = _verifier;
    }

    /**
     * @dev Submit proof of solvency for a CEX
     * @param exchangeId The ID of the exchange
     * @param cexAddresses The CEX addresses
     * @param cexSignatures The signatures of a message "Summa proof of solvency for {exchangeId}" for each CEX address
     * @param erc20ContractAddresses The addresses of the ERC20 token contracts that the CEX holds (e.g., USDT, USDC, DAI)
     * @param balancesToProve The balances to prove. ETH balance should be the first element, followed by ERC20 balances in the order of erc20ContractAddresses
     * @param mstRoot The root of the Merkle sum tree
     * @param proof The ZK proof
     */
    function submitProofOfSolvency(
        string memory exchangeId,
        address[] memory cexAddresses,
        bytes[] memory cexSignatures,
        address[] memory erc20ContractAddresses,
        uint256[] memory balancesToProve,
        uint256 mstRoot,
        bytes memory proof
    ) public {
        require(
            cexAddresses.length == cexSignatures.length &&
                cexAddresses.length > 0,
            "CEX addresses and signatures count mismatch"
        );

        require(
            erc20ContractAddresses.length == balancesToProve.length - 1 &&
                erc20ContractAddresses.length > 0,
            "ERC20 addresses and balances count mismatch"
        );

        uint256 totalETHBalance = 0;
        uint256[] memory erc20Balances = new uint256[](
            erc20ContractAddresses.length
        );
        for (uint i = 0; i < cexAddresses.length; i++) {
            // Check that message is "summa proof of solvency {exchangeId}" and the signature is valid
            address recoveredPubKey = keccak256(
                abi.encode("Summa proof of solvency for ", exchangeId)
            ).toEthSignedMessageHash().recover(cexSignatures[i]);
            require(
                cexAddresses[i] == recoveredPubKey,
                "Invalid signer for ETH address"
            );

            totalETHBalance += cexAddresses[i].balance;
            for (uint j = 0; j < erc20ContractAddresses.length; j++) {
                erc20Balances[j] += IERC20(erc20ContractAddresses[j]).balanceOf(
                    cexAddresses[i]
                );
            }
        }

        require(
            totalETHBalance >= balancesToProve[0],
            "Actual ETH balance is less than the proven balance"
        );

        for (uint i = 0; i < erc20ContractAddresses.length; i++) {
            require(
                erc20Balances[i] >= balancesToProve[i + 1],
                "Actual ERC20 balance is less than the proven balance"
            );
        }

        uint256[] memory inputs = new uint256[](balancesToProve.length + 1);
        inputs[0] = mstRoot;

        for (uint i = 0; i < balancesToProve.length; i++) {
            inputs[i + 1] = balancesToProve[i];
        }

        // Verify ZK proof
        require(verifyZkProof(proof, inputs), "Invalid zk proof");

        bytes32 exchangeIdHash = keccak256(abi.encode(exchangeId));
        emit ProofOfSolvencySubmitted(exchangeIdHash, mstRoot);
    }

    function verifyZkProof(
        bytes memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        return verifier.verify(publicInputs, proof);
    }
}
