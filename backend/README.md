# Backend

This directory contains the backend implementation for the Summa Proof of Solvency protocol.

## Core Components

### Round

The `Round` component represents a specific period or cycle in the Summa Proof of Solvency protocol. It encapsulates the state of the system at a given time, including the snapshot of assets and liabilities, as well as the associated proofs. 
 The `Round` struct integrates with the `Snapshot` and `SummaSigner` to facilitate the generation and submission of proofs to the contract.

Key Features:
- Initialization of a new round with specific parameters.
- Building a snapshot of the current state.
- Dispatching solvency proofs to the contract.
- Retrieving proofs of inclusion for specific users.

### AddressOwnership

The `AddressOwnership` component is responsible for managing and verifying the ownership of addresses. It ensures that addresses used in the protocol owned by the respective participants. This component interacts with the `SummaSigner` to submit proofs of address ownership to on-chain.

Key Features:
- Initialization with specific signer details.
- Dispatching proofs of address ownership to the contract.

## Prerequisites

The `ptau` file, containing the Powers of Tau trusted setup parameters needed to build the zk circuits, is already included. However, if you wish to test or run the code with a higher number of entries, you may choose to download a different `ptau` file.

You can find the necessary files at https://github.com/han0110/halo2-kzg-srs. To download a specific file, you can use:

```
wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/hermez-raw-11
```

After downloading, pass the path to the desired file to the `Snapshot::new` method. If you are using the included `ptau` file, no additional steps are necessary.

## Running Test

To build the binary executable and test it

```
cargo build
SIGNATURE_VERIFICATION_MESSAGE="Summa proof of solvency for CryptoExchange" cargo test --release -- --nocapture
```

## Important Notices

### Generating Verifiers for Backend

The following steps are optional and are only required if you need to update the verifier contracts for the backend:

1. **Build the Verifier Contracts**:
    - Move to the `zk_prover` directory.
    - Run the [`gen_solvency_verifier`](https://github.com/summa-dev/summa-solvency/blob/master/zk_prover/examples/gen_solvency_verifier.rs) and [`gen_inclusion_verifier`](https://github.com/summa-dev/summa-solvency/blob/master/zk_prover/examples/gen_inclusion_verifier.rs) located within the `zk_prover/examples`.
    - For detailed instructions [building a solvency verifier contract](https://github.com/summa-dev/summa-solvency/tree/master/zk_prover#build-a-solvency-verifier-contract) and [building an inclusion verifier contract.](https://github.com/summa-dev/summa-solvency/tree/master/zk_prover#build-an-inclusion-verifier-contract)
2. **Deploy Contracts to Local Environment**: 
    - Navigate to the `contracts` directory
    - Deploy the contracts to a Hardhat environment. This step will refresh the ABI files(`src/contracts/abi/*.json`) in the backend.
3. **Generate Rust Interface Files**: 
    - Move to the `backend` directory.
    - Execute the build script in the backend. This will produce the Rust interface files: `inclusion_verifier.rs`, `solvency_verifier.rs`, and `summa_contract.rs`.

By completing these steps, the backend will be primed with the essential verifiers for its tasks.

## Examples

### Running the Inclusion Verification

This example demonstrates how a user can verify the inclusion of their account in the Merkle Sum Tree. 
In this example, the CEX provides the user with their `balances` and `username`, but not the `leaf_hash`. 

The user will generate the `leaf_hash` themselves and then verify its inclusion in the tree.

Make sure you have the required files:
- `backend/ptau/hermez-raw-11`
- `backend/src/apis/csv/assets.csv`
- `zk_prover/src/merkle_sum_tree/csv/entry_16.csv`


To run the example:
```
cargo run --example verify_inclusion
```

On successful execution, you'll observe a message indicating the verification outcome:
```
Verifying the proof result for User #0: true
```
