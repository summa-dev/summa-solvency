use ethers::prelude::Abigen;
use std::{fs::OpenOptions, io::Write, path::PathBuf};

fn main() {
    let contracts = [
        (
            "src/contracts/generated/summa_contract.rs",
            "Summa",
            "Summa",
        ),
        (
            "src/contracts/generated/inclusion_verifier.rs",
            "InclusionVerifier",
            "InclusionVerifier",
        ),
    ];

    let mut submodule_names = Vec::new();
    for (out_path, contract_name, abi_source) in contracts.iter() {
        if let Some(submodule_name) =
            generate_rust_contract_interface(out_path, contract_name, abi_source)
        {
            submodule_names.push(submodule_name);
        }
    }

    let mod_out_file: PathBuf = std::env::current_dir()
        .unwrap()
        .join("src/contracts/generated/mod.rs");
    if mod_out_file.exists() {
        std::fs::remove_file(&mod_out_file).unwrap();
    }

    let mut mod_file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(mod_out_file)
        .unwrap();

    let final_content = submodule_names
        .iter()
        .map(|name| format!("pub mod {};", name))
        .collect::<Vec<String>>()
        .join("\n");

    mod_file.write_all(final_content.as_bytes()).unwrap();
}

fn generate_rust_contract_interface<'a>(
    out_path: &'a str,
    contract_name: &str,
    abi_source: &str,
) -> Option<&'a str> {
    let contract_out_file = std::env::current_dir().unwrap().join(out_path);
    if contract_out_file.exists() {
        std::fs::remove_file(&contract_out_file).unwrap();
    }

    Abigen::new(
        contract_name,
        format!("./src/contracts/abi/{}.json", abi_source),
    )
    .unwrap()
    .format(true)
    .generate()
    .unwrap()
    .write_to_file(contract_out_file)
    .unwrap();

    let submodule_name = out_path
        .rsplit('/') // Split the string from the right at each /
        .next() // Take the substring right after the last /
        .and_then(|s| s.split('.').next()); // Take the substring before the first . (from the right)

    submodule_name
}
