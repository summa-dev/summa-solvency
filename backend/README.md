# Backend for Summa with CLI

 The application includes CLI tools for Centralized Exchange (CEX) operators and users to generate and verify proofs, using structures like `SummaSigner` and `Snapshot`. 
 
 Detailed documentation and additional features will be added in the future.

## Prerequisites

For the CLI application to work correctly, you need to download the Powers of Tau files.

You can find these important files at https://github.com/han0110/halo2-kzg-srs and they should be placed in a `ptau` folder.

To run the tests, you need to download two specific ptau files, `hermez-raw-10` and `hermez-raw-11`. You can download these files with the following steps:

```
mkdir ptau
cd ptau
wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/hermez-raw-10
wget https://trusted-setup-halo2kzg.s3.eu-central-1.amazonaws.com/hermez-raw-11
```
