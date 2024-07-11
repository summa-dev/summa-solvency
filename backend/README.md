# Backend

This directory contains the backend implementation for the Summa Proof of Solvency protocol.

## Core Components

### Round

The `Round` component represents a specific period or cycle in the Summa Proof of Solvency protocol. It encapsulates the state of the system at a given time, including the snapshot of assets and liabilities, as well as the associated proofs.
The `Round` struct integrates with the `Snapshot` to facilitate the generation of proofs.

Key Features:

- Initialization of a new round with specific parameters.
- Building a snapshot of the current state.
- Generating commitment and verifier parameters used in the verification process.
- Retrieving proofs of inclusion for specific users.

## Prerequisites

Before testing or running the Summa backend, you must download the ptau file, which contains the Powers of Tau trusted setup parameters essential for building the ZK circuits. Specifically, the `hermez-raw-hyperplonk-17` file is required for the [Summa flow](./examples/summa_solvency_flow.rs) example and its associated test case.

You can find this and other necessary files at https://github.com/sifnoc/halo2-kzg-srs. To download `hermez-raw-hyperplonk-17`, use the following command:

```
wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/hermez-raw-plonkish-17
```

Ensure this file is downloaded before proceeding with the example or test case.

## Running Test

To build the binary executable and test it, use the following commands:

```
cargo build
cargo test --release -- --nocapture
```

## Summa solvency flow example

This example illustrates how Summa can generate commitment proofs and verifier parameters, and then verify inclusion proofs on the user side.

To execute this example, use the command:

```
cargo run --release --example summa_solvency_flow
```

### 1. Generate Commitment

The CEX must publicly share a commitment for each round. This commitment consists of a timestamp, a grand sum proof, and total balances.

Without the CEX publishing the commitment, users cannot verify their inclusion proofs. This is because the inclusion verifier function internally requires the commitment, which is a SNARK proof along with Verifier Parameters.

In this step, we'll guide you through the process of generating a commitment using the `Round` component.
The `Round` serves as the core of the backend in Summa, and we have briefly described it in the Components section.

To initialize the `Round` instance, you'll need the paths to the liabilities CSV file (`entry_16.csv`) and the `ptau/hermez-raw-plonkish-17` file. These files serve the following purposes:

- `entry_16.csv`: contains the username and liabilities entries for each CEX user (necessary to build the commitment). Liabilities column names have the following format: `balance_<CRYPTOCURRENCY>_<CHAIN>`, where <CRYPTOCURRENCY> and <CHAIN> are the names of the cryptocurrencies and their corresponding blockchains.
- `ptau/hermez-raw-plonkish-17`: contains parameters for constructing the zk circuits.

If this step runs successfully, you will see the following message:

```
1. Commitment and Verifier Parameters successfully Exported!
```

### 2. Generating and Exporting Inclusion Proofs

Assuming you're a CEX, after committing the commitment publicly, you should generate inclusion proofs for every user. This proof verifies the presence of specific elements in the polynomials encoding the username and balances.

After generating the inclusion proof, it is transformed into a JSON format for easy sharing.

Upon successful execution, you'll find a file named `user_0_proof.json` and see the following message:

```
2. Exported proof to user #0, as `user_0_proof.json`, with verifier params `verifier_params.json`
```

Note that the `verifier_params.json` file can be used in any other round unless the same circuit configurations, such as `N_CURRENCIES` and `K`.

### 3. Verify Proof of Inclusion

This is the final step in the Summa process and the only part that occurs on the user side.

Users receive the proof and commitment for a specific round along with the verifier parameters. Unlike the commitment and proof, the verifier parameters are independent of the round.

In this step, the user has to:

- Ensure that the user values in the proof file align with the `username` and `balances` provided by the CEX.
- Perform the verifier locally with commitment and verifier parameters files.

The result will be displayed as:

```
3. Verified the proof with veirifer parameters for User #0: true
```
