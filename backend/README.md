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

The sequence in which the examples are introduced closely relates to the steps of the Summa protocol.
These examples will help to understand how the Summa works with the Summa contract and the user side.


### 1. Generating Message Signatures

This example illustrates how to generate a CSV file containing signatures derived from a specific message, crucial for establishing `AddressOwnership`.
Creating the `signatures.csv` file is a preliminary step for initializing a `Round` in Summa.

This demonstration is introduced to be adaptable across various scenarios. For instance, you can compile this example that modified to support harware wallet into an executable binary, enabling an operator to run it with a hardware wallet. This operation should ideally be conducted within a secure environment inside a CEX, ensuring the system is isolated from any online networks to maximize protection against potential external threats.

The generated signatures are stored in a CSV file, utilizing a custom delimiter for easy parsing and verification. The output file is located at `src/apis/csv/signatures.csv`.

To run the example:
```
cargo run --example generate_signatures
```

Note: While this example employs hardcoded private keys for simplicity, it's essential to remember that exposing private keys directly in real-world applications can pose serious security risks. Therefore, it's recommended to create your own `signer` that taps into secure mechanisms, such as hardware wallets or protected key vaults.

### 2. Submitting Address Ownership to the Summa Contract

This example demonstrates the process of submitting proof of address ownership to the Summa contract. After generating signatures for asset ownership (as shown in the `generate_signature` example), this step is essential to register those proofs on-chain, facilitating the validation of asset ownership within Summa.

In this example, a test environment is set up with the anvil instance by invoking the `initialize_test_env` method. This environment is also utilized in other examples such as `submit_solvency` and `verify_inclusion_on_contracts`.

Key points to note:

The instance of `AddressOwnership` is initialized with `signatures.csv`, and is named `address_ownership_client`. This instance has already loaded the signature data.

The `dispatch_proof_of_address_ownership` function sends a transaction to the Summa contract, registering the addresses owned by the CEX on the contract.

After dispatching the transaction via `dispatch_proof_of_address_ownerhip`, the example computes the hashed addresses (address_hashes) to verify they have been correctly registered on the Summa contract.

To execute this example:
```
cargo run --example submit_ownership
```

Upon successful execution, you should see the message:
```
Ownership proofs are submitted successfully!
```

Reminder: This demonstration takes place in a test environment. In real-world production, always ensure that the Summa contract is correctly deployed on the target chain.

### 3. Submit Proof of Solvency

Before generate inclusion proof for every user of the current round, You should submit proof of sovlency to Summa contract. Currently, we made this as mandatory way to commit the root hash of the Merkle Sum Tree.

Without this process, It seems the user may not trust to the inclusion proof for the round. becuase the `mst_root` is not published on contract. More specifically, it means that the `mst_root` is not correctly verified on the Summa contract.

In this example, we'll guide you through the process of submitting a solvency proof using the Round to the Summa contract.
The Round serves as the core of the backend in Summa, and we have briefly described it in the Components section.

To initialize the Round, several parameters are required, including paths to specific CSV files (`assets.csv` and `entry_16.csv`), as well as a path to the ptau file (`ptau/hermez-raw-11`).

The roles of these files are as follows:
- `assets.csv`: This file is essential for calculating the total balance of assets for the solvency proof. Currently, only the CEX can generate this asset CSV file in its specific manner.

- `entry_16.csv`: This file is used to build the Merkle sum tree, where each leaf element originates from sixteen entries in the CSV.
X
- `ptau/hermez-raw-11`: Contains the Powers of Tau trusted setup parameters, essential for constructing the zk circuits.

An instance of Round dispatches the solvency proof using the `dispatch_solvency_proof` method.

To execute this example:
```
cargo run --example submit_solvency
```

Upon successful execution, you will see the message:

```
 "Solvency proof is submitted successfully!"
```

### 4. Generating and Exporting Inclusion Proofs

Assuming you are a CEX, let's say you've already committed the `solvency` and `ownership` proofs to the Summa contract. Now, you need to generate inclusion proofs for every user.

In this example, we demonstrate how to generate and export user-specific inclusion proofs using the Round. This proof is crucial for users as it helps them validate the presence of specific elements within the Merkle sum tree, which forms a part of the solvency proof submitted.

After generating the inclusion proof, end of example parts the inclusion proof is transformed into a JSON format, making it easily shareable.

To execute this example:
```
cargo run --example generate_inclusion
```

Upon successful execution, you can see this message and exported file `user_0_proof.json`.

```
 "Exported proof to user #0, as `user_0_proof.json`"
```

### 5. Verify Proof of Inclusion

This is the final step in the Summa process and the only part that occurs on the user side.

The user will receive the proof for a specific Round. There are two ways to verify the proof, one is on binary verifier in local environment, another is that the verifier function on the Summa contract.

In the `verify_inclusion_on_local` example, the key part is that use `full_evm_verifier` method for verifying the proof with publicly downloaded `ptau` file.
We can think the demonstration of verifying in the example is that only shown excutable local verifier that is served from CEX in publicly way, such as github, or IPFS.

To run the verify inclusion on local example:
```
cargo run --example verify_inclusion_on_local
```

Like the user #0, you will see the result like:
```
Verifying the proof result for User #0: true
```

Another way to verify the inclusion proof, the user can use method on the Summa contract that already deployed on blockchain.

In the `verify_inclusion_on_contract` example, the procedure for verifying the inclusion proof using an on-chain method is illustrated. By leveraging the data from the Summa contract, users can effortlessly ascertain that the provided proof aligns with the data submitted by the CEX.

To elaborate:

Retrieving the MST Root: The user fetches the `mst_root` from the Summa contract. This root should match the `root_hash` provided in the proof. This verification process is akin to ensuring that the `leaf_hash` corresponds with the anticipated hash based on the `username` and `balances` provided by the CEX.

On-chain Function Verification: The user then invokes the `verify_inclusion_proof` method on the Summa contract. Since this is a view function, it returns a boolean value without incurring any gas fees, indicating the success or failure of the verification.

To run the verify inclusion on contract example:
```
cargo run --example verify_inclusion_on_contract
```

You will see the result like:
```
Verifying the proof on contract veirifer for User #0: true
```


With the `verify_inclusion_on_local` and `verify_inclusion_on_contract` examples at their disposal, users are equipped with options, allowing them to choose their preferred verification method, be it local or on-chain. Moreover, by employing both verification strategies, users can achieve a heightened level of trust and transparency.
