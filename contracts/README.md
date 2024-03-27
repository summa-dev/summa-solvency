# Summa Smart Contract

The [Summa smart contract](src/Summa.sol) serves as a registrar for Custodians to affirm their liabilities by submitting a polynomial commitment of all liabilities owed to their users. Users can verify their inclusion in the liabilities commitment, allowing public comparison of the committed total sums with the assets owned by the Custodian onchain.


## Features

- **Address Ownership Proofs**: Custodians should submit proof of address ownership for all addresses holding assets included in the commitment using the `submitProofOfAddressOwnership` function. These proofs are accepted optimistically and subject to off-chain verification.

- **Liabilities Commitments**: Custodians can commit to their liabilities in the form of polynomial commitments and the corresponding total sums representing snapshots of the liabilities at a given timestamp through the `submitCommitment` function.

- **Inclusion Verification**: Users can verify the polynomial commitment of their balances into the liabilities using the `verifyInclusionProof` function. This function calls the underlying smart contract [InclusionVerifier](src/InclusionVerifier.sol) module. refer to the module's [readme](./../prover/README.md) for details.


## Installation

Ensure you have Node.js installed on your machine before proceeding. The smart contract is written in Solidity and uses the Hardhat environment for testing and deployment.

To set up the project environment, install the necessary dependencies:

```shell
npm install
```

## Testing

```shell
npx hardhat node
REPORT_GAS=true npx hardhat test
```

### Test Coverage

```shell
npx hardhat coverage
```

## Deploying

```shell
npx hardhat run scripts/deploy.ts
```

The Summa contract deployment script is designed to streamline setup by automatically deploying three verifier contracts along with one verifying key contract. It then configures the deployment with specific parameters, which include:

- The number of currencies;
- the number of bytes used to represent the balance of a cryptocurrency in the polynomials;

The deployment script updates the latest deployment address for the chain in the  [deployments](./../backend/src/contracts/deployments.json) file in the backend. This allows the backend module to connect to the deployed contract seamlessly.

Additionally, the script transfers the contract ABIs from `./artifacts/src/` to the [backend](./../backend/src/contracts/abi/) module. Subsequently, the backend build script generates the updated contract interfaces (for more details, see the backend [readme](./../backend/README.md)).
