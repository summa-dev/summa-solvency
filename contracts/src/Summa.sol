// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

// Uncomment this line to use console.log
//import "hardhat/console.sol";

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

interface IVerifier {
    function verify(
        uint256[] calldata pubInputs,
        bytes calldata proof
    ) external view returns (bool);
}

contract Summa is Ownable {
    using ECDSA for bytes32;

    IVerifier private immutable verifier;

    address[] public cexAddresses;

    event ExchangeAddressesSubmitted(address[] cexAddresses);

    event ProofOfSolvencySubmitted(uint256 indexed mstRoot);

    constructor(IVerifier _verifier) {
        verifier = _verifier;
    }

    function submitProofOfAccountOwnership(
        address[] memory _cexAddresses,
        bytes[] memory cexSignatures,
        string memory message
    ) public {
        require(
            _cexAddresses.length == cexSignatures.length &&
                _cexAddresses.length > 0,
            "CEX addresses and signatures count mismatch"
        );

        for (uint i = 0; i < _cexAddresses.length; i++) {
            if (i >= cexAddresses.length) {
                cexAddresses.push(_cexAddresses[i]);
            } else if (_cexAddresses[i] != cexAddresses[i]) {
                cexAddresses[i] = _cexAddresses[i];
            }
            address recoveredPubKey = keccak256(abi.encode(message))
                .toEthSignedMessageHash()
                .recover(cexSignatures[i]);
            require(
                _cexAddresses[i] == recoveredPubKey,
                "Invalid signer for ETH address"
            );
        }

        // Since we're always rewriting the old array with the new values, we need to make sure that we remove any leftovers if the new set of addresses is smaller than the old one
        // TODO - explore some gas-efficient ways of maintaining this array
        if (_cexAddresses.length < cexAddresses.length) {
            for (uint i = _cexAddresses.length; i < cexAddresses.length; i++) {
                cexAddresses.pop();
            }
        }

        emit ExchangeAddressesSubmitted(cexAddresses);
    }

    /**
     * @dev Submit proof of solvency for a CEX
     * @param erc20ContractAddresses The addresses of the ERC20 token contracts that the CEX holds (e.g., USDT, USDC, DAI)
     * @param assetSums The total asset sums to prove. ETH balance should be the first element, followed by ERC20 balances in the order of erc20ContractAddresses
     * @param mstRoot The root of the Merkle sum tree
     * @param proof The ZK proof
     */
    function submitProofOfSolvency(
        address[] memory erc20ContractAddresses,
        uint256[] memory assetSums,
        uint256 mstRoot,
        bytes memory proof
    ) public {
        require(
            erc20ContractAddresses.length == assetSums.length - 1 &&
                erc20ContractAddresses.length > 0,
            "ERC20 addresses and balances count mismatch"
        );

        uint256 totalETHBalance = 0;
        uint256[] memory erc20Balances = new uint256[](
            erc20ContractAddresses.length
        );
        for (uint i = 0; i < cexAddresses.length; i++) {
            totalETHBalance += cexAddresses[i].balance;
            for (uint j = 0; j < erc20ContractAddresses.length; j++) {
                erc20Balances[j] += IERC20(erc20ContractAddresses[j]).balanceOf(
                    cexAddresses[i]
                );
            }
        }

        require(
            totalETHBalance >= assetSums[0],
            "Actual ETH balance is less than the proven balance"
        );

        for (uint i = 0; i < erc20ContractAddresses.length; i++) {
            require(
                erc20Balances[i] >= assetSums[i + 1],
                "Actual ERC20 balance is less than the proven balance"
            );
        }

        uint256[] memory inputs = new uint256[](assetSums.length + 1);
        inputs[0] = mstRoot;

        for (uint i = 0; i < assetSums.length; i++) {
            inputs[i + 1] = assetSums[i];
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
