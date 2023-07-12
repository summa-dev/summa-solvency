use std::{fs::OpenOptions, io::Write, path::PathBuf};

use ethers::prelude::Abigen;

fn main() {
    let contract_out_file = std::env::current_dir()
        .unwrap()
        .join("src/contracts/generated/summa_contract.rs");
    if contract_out_file.exists() {
        std::fs::remove_file(&contract_out_file);
    }

    Abigen::new("Summa", "./src/contracts/contractAbi.json")
        .unwrap()
        .format(true)
        .generate()
        .unwrap()
        .write_to_file(contract_out_file);

    let mod_out_file: PathBuf = std::env::current_dir()
        .unwrap()
        .join("src/contracts/generated/mod.rs");
    if mod_out_file.exists() {
        std::fs::remove_file(&mod_out_file);
    }

    let mut mod_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(mod_out_file)
        .unwrap();

    mod_file
        .write_all(b"pub mod summa_contract;\npub mod verifier;\npub mod mock_erc20;")
        .unwrap();

    let contract_out_file = std::env::current_dir()
        .unwrap()
        .join("src/contracts/generated/mock_erc20.rs");
    if contract_out_file.exists() {
        std::fs::remove_file(&contract_out_file);
    }

    Abigen::new("MockERC20", "./src/contracts/MockERC20.json")
        .unwrap()
        .format(true)
        .generate()
        .unwrap()
        .write_to_file(contract_out_file);

    let contract_out_file = std::env::current_dir()
        .unwrap()
        .join("src/contracts/generated/verifier.rs");
    if contract_out_file.exists() {
        std::fs::remove_file(&contract_out_file);
    }

    Abigen::new("SolvencyVerifier", "./src/contracts/Verifier.json")
        .unwrap()
        .format(true)
        .generate()
        .unwrap()
        .write_to_file(contract_out_file);
}
