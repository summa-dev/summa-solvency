use std::io::Write;
use std::{fs::File, path::Path};

use bincode;
use dialoguer::{Input, Select};
use serde::{Deserialize, Serialize};

use summa_backend::apis::snapshot::Snapshot;

#[derive(Serialize, Deserialize)]
pub struct InclusionProofExport {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
}

fn main() {
    const N_ASSETS: usize = 2;
    const L: usize = 2 + (N_ASSETS * 2);
    const LEVELS: usize = 4;
    const N_BYTES: usize = 64 / 8;
    const K: u32 = 11;

    // Prompt for exchange ID
    let exchange_id: String = Input::new()
        .with_prompt("Enter exchange ID")
        .validate_with(|input: &String| -> Result<(), &str> {
            if input.is_empty() {
                Err("Exchange ID cannot be empty")
            } else {
                Ok(())
            }
        })
        .interact()
        .unwrap();

    // Prompt for contract address
    let contract_address: String = Input::new()
        .with_prompt("Enter contract address")
        .interact()
        .unwrap();

    // Prompt for private key
    let private_key: String = Input::new()
        .with_prompt("Enter private key for Signer")
        .interact()
        .unwrap();

    // Initialize the Snapshot
    let mut snapshot: Snapshot<LEVELS, L, N_ASSETS, N_BYTES, K> =
        Snapshot::new(&exchange_id, &contract_address);

    // Prompt for entry CSV file path
    let entry_csv: String = Input::new()
        .with_prompt("Enter path to entry CSV file")
        .with_initial_text("entry_16.csv")
        .interact()
        .unwrap();

    if !Path::new(&entry_csv).exists() {
        eprintln!("File not found: {}", entry_csv);
        return;
    }

    // Prompt for asset CSV file path
    let asset_csv: String = Input::new()
        .with_prompt("Enter path to asset CSV file")
        .with_initial_text("assets_2.csv")
        .interact()
        .unwrap();

    if !Path::new(&asset_csv).exists() {
        eprintln!("File not found: {}", entry_csv);
        return;
    }

    // Initialize the Snapshot data
    if let Err(error) = snapshot.init_data(&entry_csv, &asset_csv) {
        eprintln!("Error initializing Snapshot data: {}", error);
        return;
    }

    loop {
        let selections = &[
            "1. Generate on-chain proof",
            "2. Verify on-chain proof",
            "3. Export User proof",
            "4. Exit",
        ];

        let selection = Select::new()
            .with_prompt("Choose an action")
            .default(0)
            .items(selections)
            .interact()
            .unwrap();

        match selection {
            0 => {
                let result = snapshot.generate_proof();

                if result.is_ok() {
                    println!("Sucessfully generate onchain proof");
                    if snapshot.data.is_some() {
                        let snapshot_data = snapshot.data.as_ref().unwrap();
                        let solvency_proof = snapshot_data.get_onchain_proof().unwrap();
                        println!(
                            "onchain_proof root_hash: {:?}",
                            solvency_proof.get_root_hash()
                        );
                    }
                } else {
                    println!("Error generating onchain proof: {:?}", result);
                }
            }
            1 => {
                println!("Verifying on-chain proof");
            }
            2 => {
                let user_index: u64 = Input::new()
                    .with_prompt("Enter user number")
                    .interact()
                    .unwrap();
                #[allow(unused_mut)]
                let mut snapshot_data = snapshot.data.as_mut().unwrap();
                let user_proof = snapshot_data.get_user_proof(user_index).unwrap();

                let export_user_roof = InclusionProofExport {
                    vk: user_proof.get_vk_vec(),
                    proof: user_proof.get_proof(),
                };

                let encoded: Vec<u8> = bincode::serialize(&export_user_roof).unwrap();

                let file_name: String = Input::new()
                    .with_prompt("Enter proof file name for exporting")
                    .with_initial_text("proof.bin")
                    .interact()
                    .unwrap();

                let mut file = File::create(&file_name).unwrap();
                file.write_all(&encoded).unwrap();

                println!("Exported user proof to {}", file_name);
            }
            3 => break,          // Exit the loop
            _ => unreachable!(), // Catch all other cases, this should be unreachable
        }
    }
}
