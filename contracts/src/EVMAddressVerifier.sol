// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.18;

import "./Summa.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract EVMAddressVerifier is IAddressOwnershipVerifier {
    using ECDSA for bytes32;

    function verifyAddressOwnership(
        bytes memory cexAddress,
        bytes memory addressOwnershipProof
    ) external pure override returns (bool) {
        address addressToVerify = abi.decode(cexAddress, (address));
        address recoveredPubKey = keccak256(
            abi.encode("Summa proof of solvency for CryptoExchange")
        ).toEthSignedMessageHash().recover(addressOwnershipProof);
        return addressToVerify == recoveredPubKey;
    }
}
