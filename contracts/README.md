# Summa Smart Contract

The [Summa smart contract](src/Summa.sol) acts as a registrar for Centralized Exchanges (CEXs) to commit to their liabilities by submitting a Merkle sum tree (MST) root of all the CEX liabilities owed to its users. Users can then verify their inclusion into the liabilities commitment, and the public can compare the committed total sums with the assets owned by the CEX onchain.

## Features

- **Address Ownership Proofs**: CEXs should submit the proof of address ownership for all addresses that hold the assets included into the commitment by using `submitProofOfAddressOwnership` function. The proofs are accepted optimistically and subject to off-chain verification.

- **Liabilities Commitments**: CEXs can submit commitments to its liabilities in the form of MST roots and the corresponding total sums that represent the snapshots of the liabilities at a given timestamp by using `submitCommitment` function.

- **Inclusion Verification**: Users are able to verify the zero-knowledge proof of inclusion of their balances into the MST using `verifyInclusionProof` function. The function is calling the underlying smart contract [Verifier](src/InclusionVerifier.sol). The verifier is generated from the [zk_prover](./../zk_prover/) module (see module's [readme](./../zk_prover/README.md)).

## Installation

Ensure you have Node.js installed on your machine before proceeding. The smart contract is written in Solidity and uses the Hardhat environment for testing and deployment.

To set up the project environment, install the necessary dependencies:

```shell
npm install
```

## Testing

```shell
REPORT_GAS=true npx hardhat test
```

### Test Coverage

```shell
npx hardhat coverage
```

## Deploying

The deployment script writes the latest deployment address for the chain to the [deployments](./../backend/src/contracts/deployments.json) file in the backend project. This data can later be used by the backend module to connect to the deployed contract.
The deployment script will copy the contract ABIs from the ./artifacts/src/ to the [backend](./../backend/src/contracts/abi/) module. The backend buildscript will then be able to generate the updated contract interfaces (see the backend [readme](./../backend/README.md)).

When deploying locally, don't forget to run the node:

```shell
npx hardhat node
```

The deployment script takes a `--network` argument. The networks can be configured in [hardhat.config.ts](hardhat.config.ts). The following is an example of a local deployment:

```shell
npx hardhat run scripts/deploy.ts --network localhost
```

The following Summa contract parameters are passed to its constructor inside the deployment script:

- verifier contract address (set automatically after the script deploys the verifier);
- the number of levels of the Merkle sum tree;
- the number of bytes used to represent the balance of a cryptocurrency in the Merkle sum tree.
