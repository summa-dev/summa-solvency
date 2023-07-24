# Backend

This directory contains the backend implementation for the Summa Proof of Solvency protocol.

The core datastructure is the `Snapshot` struct, a data container for:

- the CEX liabilities, represented via a `MerkleSumTree`
- the CEX wallets, represented via the `WalletOwnershipProof` struct.
- the Trusted Setup parameters for the `MstInclusionCircuit` and `SolvencyCircuit` zk circuits.

Furthermore, the `Snapshot` struct contains the following methods:

- `generate_solvency_verifier` -> write the Solidity Verifier contract (for the `SolvencyProof`) to a file
- `generate_proof_of_solvency` -> generate the `SolvencyProof` for the current snapshot to be verified on-chain
- `generate_inclusion_proof` -> generate the `MstInclusionProof` for a specific user for the current snapshot to be verified off-chain
- `get_account_onwership_proof` -> generate the `AccountOwnership` for a specific user for the current snapshot to be verified off-chain

## Prerequisites

In order to initialize the Snapshot, you need to download the Powers of Tau files. These are the trusted setup parameters needed to build the zk circuits. You can find such files at https://github.com/han0110/halo2-kzg-srs, download it

```
wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/hermez-raw-11
```

and pass the path to the file to the `Snapshot::new` method.

Furthermore, the `generate_proof_of_solvency` method requires to fetch data about the balances of the wallets of the CEX. This data is fetched using the Covalent API. In order to use this method, you need to create an `.env` file and store the `COVALENT_API_KEY` there. You can get an API key at https://www.covalenthq.com/platform/.

## Usage

To build the binary executable and test it

```
cargo build
SIGNATURE_VERIFICATION_MESSAGE="Summa proof of solvency for CryptoExchange" cargo test --release -- --nocapture
```

To generate the Rust contract interfaces from the ABI files, run:

```
cargo run --example contract_interface_gen
```

The [Summa contract ABI json](./src/contracts/Summa.json) is updated when the contract is deployed from the [contracts subproject](./../contracts/README.md).
