use std::io::Write;
use std::{fs::File, path::Path};

use bincode;
use dialoguer::{Input, Select};
use serde::{Deserialize, Serialize};

use summa_backend::apis::snapshot_data::SnapshotData;

#[derive(Serialize, Deserialize)]
pub struct InclusionProofExport {
    pub proof: Vec<u8>,
}

fn export_data<T>(data: &T, file_name: &str, description: &str)
where
    T: Serialize,
{
    let encoded: Vec<u8> = bincode::serialize(&data).unwrap();

    let mut file = File::create(&file_name).unwrap();
    file.write_all(&encoded).unwrap();

    println!("Exported {} to {}", description, file_name);
}

fn main() {
    // TODO: intialize the Snapshot without using these constant, use directly.
    const N_ASSETS: usize = 2;
    const L: usize = 2 + (N_ASSETS * 2);
    const LEVELS: usize = 15;
    const N_BYTES: usize = 64 / 8;
    const K: u32 = 13;

    // TODO: check if this is necessary, remove if not
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

    // Prompt for entry CSV file path
    let entry_csv: String = Input::new()
        .with_prompt("Enter path to entry CSV file")
        .with_initial_text("../zk_prover/src/merkle_sum_tree/csv/two_assets_entry_2_15.csv")
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

    // Initialize the SnapshotData
    let mut snapshot_data: SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K> = SnapshotData::new(
        &exchange_id,
        &entry_csv,
        &asset_csv,
        Some("artifacts/mst_inclusion_15_6_2.pk"),
    )
    .unwrap();

    loop {
        let selections = &[
            "1. Export solvency proof for the verifier contract",
            "2. Export MST inclusion proof for a user",
            "3. Exit",
        ];

        let selection = Select::new()
            .with_prompt("Choose an action")
            .default(0)
            .items(selections)
            .interact()
            .unwrap();

        match selection {
            0 => {
                let proving_key_path = "artifacts/solvency_6_2_8.pk";
                let result = snapshot_data.generate_solvency_proof(&proving_key_path);

                if result.is_ok() {
                    println!("Sucessfully generate solvency proof");
                    let solvency_proof = snapshot_data.get_solvency_proof().unwrap();
                    println!(
                        "solvency proof root_hash: {:?}",
                        solvency_proof.get_root_hash()
                    );
                } else {
                    println!("Error generating solvency proof: {:?}", result);
                }
            }
            1 => {
                let user_index: u64 = Input::new()
                    .with_prompt("Enter user number")
                    .interact()
                    .unwrap();

                let inclusion_proof = snapshot_data.get_mst_inclusion_proof(user_index).unwrap();

                let _export_inclusion_proof = InclusionProofExport {
                    // vk: inclusion_proof.get_vk_vec(),
                    proof: inclusion_proof.get_proof(),
                };

                let file_name: String = Input::new()
                    .with_prompt("Enter proof file name for exporting")
                    .with_initial_text("proof.bin")
                    .interact()
                    .unwrap();

                export_data::<Vec<u8>>(&inclusion_proof.get_proof(), &file_name, "inclusion proof");

                // // TODO: check necessary, remove if not
                // let encoded: Vec<u8> = bincode::serialize(&inclusion_proof.get_vk_vec()).unwrap();

                // let file_name: String = Input::new()
                //     .with_prompt("Enter vk file name for exporting")
                //     .with_initial_text("vk.bin")
                //     .interact()
                //     .unwrap();

                // let mut file = File::create(&file_name).unwrap();
                // file.write_all(&encoded).unwrap();
            }
            2 => break,          // Exit the loop
            _ => unreachable!(), // Catch all other cases, this should be unreachable
        }
    }
}
