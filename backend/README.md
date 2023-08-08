# Backend

This directory contains the backend implementation for the Summa Proof of Solvency protocol.

The core datastructure is the `Snapshot` struct, a data container for:

- the CEX liabilities, represented via a `MerkleSumTree`
- the CEX wallets, represented via the `WalletOwnershipProof` struct.
- the Trusted Setup parameters for the `MstInclusionCircuit` and `SolvencyCircuit` zk circuits.

Furthermore, the `Snapshot` struct contains the following methods:

- `generate_solvency_verifier` -> write the Solidity Verifier contract (for the `SolvencyProof`) to a file
- `generate_proof_of_solvency` -> generate the `SolvencyProof` for the current snapshot to be verified on-chain
- `generate_proof_of_inclusion` -> generate the `MstInclusionProof` for a specific user for the current snapshot to be verified off-chain
- `get_proof_of_account_ownership` -> generate the `AccountOwnership` for a specific user for the current snapshot to be verified off-chain

## Prerequisites

The `ptau` file, containing the Powers of Tau trusted setup parameters needed to build the zk circuits, is already included. However, if you wish to test or run the code with a higher number of entries, you may choose to download a different `ptau` file.

You can find the necessary files at https://github.com/han0110/halo2-kzg-srs. To download a specific file, you can use:

```
wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/hermez-raw-11
```

After downloading, pass the path to the desired file to the `Snapshot::new` method. If you are using the included `ptau` file, no additional steps are necessary.

## Important Notices

### For Proof of Solvency

As of the current implementation, the `generate_proof_of_solvency` method does not directly fetch data about the balances of the wallets of the CEX. Instead, you can use the `fetch_asset_sums` function to retrieve balance information from the blockchain. Here's an example of how you might utilize it:

```Rust
let asset_sums = fetch_asset_sums(client, token_contracts, exchange_addresses).await?;
```

Please note that the first element in the `asset_sums` array represents the ETH balance.

Alternatively, you can create your own custom fetcher to retrieve the balances.

### For Proof of Ownership

To generate a signed message, you must first initialize the `SummaSigner` and use the `generate_signatures` method:

```Rust
let signatures = signer.generate_signatures().await.unwrap();
```

The content of the message can be specified with the local variable `SIGNATURE_VERIFICATION_MESSAGE`.

### For Generating Solvency Verifier

The provided verifier found at `src/contracts/Verifier.json` is based on the trusted setup, `hermez-raw-11`. If you are working with a higher number of entries, you will need to generate a new verifier contract by using the `generate_solvency_verifier` method.

Here's a brief example of how you might invoke this method:

```Rust
Snapshot::generate_solvency_verifier("SolvencyVerifier.yul", "SolvencyVerifier.sol");
```

This method creates two files, `SolvencyVerifier.yul` and `SolvencyVerifier.sol`, which will be used in `Summa.sol`.

## Usage

To build the binary executable and test it

```
cargo build
SIGNATURE_VERIFICATION_MESSAGE="Summa proof of solvency for CryptoExchange" cargo test --release -- --nocapture
```

The [buildscript](./build.rs) will automatically build the contract Rust interfaces from the [JSON ABIs](./src/contracts/abi/) and place them into [./src/contracts/generated](./src/contracts/generated) directory. The ABIs are updated on contract deployment from the [contracts subproject](./../contracts/README.md) by the [contract deployment script](./../contracts/scripts/deploy.ts).
