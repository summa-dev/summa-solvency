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

## Summa solvency flow example

This example illustrates how Summa interacts with the Summa contract and the user side.

To execute this example, use the command:

```
cargo run --release --example summa_solvency_flow
```

### 1. Submitting Address Ownership to the Summa Contract

First, we submit proof of address ownership to the Summa contract. This is a critical step to register these proofs on-chain, facilitating the validation of asset ownership within Summa.

Key points:

- An instance of `AddressOwnership`, named `address_ownership_client`, is initialized with the `signatures.csv` file, which contains the signature data.

- The `dispatch_proof_of_address_ownership` function sends a transaction to the Summa contract to register CEX-owned addresses.

- After dispatching the transaction, the example computes the hashed addresses (address_hashes) to verify they've been correctly registered in the Summa contract


Note: This demonstration takes place in a test environment. In real-world production, always ensure that the Summa contract is correctly deployed on the target chain.

If executed successfully, you'll see:

```
1. Ownership proofs are submitted successfully!
```


### 2. Submit Proof of Solvency

This step is crucial for two primary reasons: first, to validate the root hash of the Merkle Sum Tree (`mst_root`); and second, to ensure that the assets held by the CEX exceed their liabilities, as confirmed through the proof verification on the Summa contract.
The CEX must submit this proof of solvency to the Summa contract. Currently, it's a mandatory requirement to provide this proof before generating the inclusion proof for each user in the current round.

Without this verification, It seems the user may not trust to the inclusion proof for the round. becuase the `mst_root` is not published on contract. More specifically, it means that the `mst_root` is not correctly verified on the Summa contract.

In this step, we'll guide you through the process of submitting a solvency proof using the Round to the Summa contract.
The Round serves as the core of the backend in Summa, and we have briefly described it in the Components section.

To initialize the `Round` instance, you'll need paths to specific CSV files (`assets.csv` and `entry_16.csv`) and the `ptau/hermez-raw-11` file. Here's what each file does:

- `assets.csv`: Calculates the total balance of assets for the solvency proof. Only the CEX can generate this file.
- `entry_16.csv`: Used to build the Merkle sum tree, with each leaf element derived from sixteen entries in the CSV.
- `ptau/hermez-raw-11`: Contains parameters for constructing the zk circuits.

Using the `Round` instance, the solvency proof is dispatched to the Summa contract with the `dispatch_solvency_proof` method.

If this step successfully ran, you can see this message:

```
2. Solvency proof is submitted successfully!
```

### 3. Generating and Exporting Inclusion Proofs

Assuming you're a CEX, after committing the `solvency` and `ownership` proofs to the Summa contract, you should generate inclusion proofs for every user. This proof verifies the presence of specific elements in the Merkle sum tree, which is part of the solvency proof.

After generating the inclusion proof, it's transformed into a JSON format for easy sharing.

Upon successful execution, you'll find a file named `user_0_proof.json` and see the following message:

```
3. Exported proof to user #0, as `user_0_proof.json`
```

### 4. Verify Proof of Inclusion

This is the final step in the Summa process and the only part that occurs on the user side.

Users receive the proof for a specific round and use methods available on the deployed Summa contract. Importantly, the Summa contract verifier function is a view function, meaning it doesn't consume gas or change the blockchain's state.

In this step, you'll see:

- Retrieve the `mst_root` from the Summa contract and match it with the `root_hash` in the proof.
- Ensure the `leaf_hash` aligns with the hash based on the `username` and `balances` provided by the CEX.
- Use the `verify_inclusion_proof` method on the Summa contract to validate the proof.

The result will display as:
```
4. Verifying the proof on contract verifier for User #0: true
```
