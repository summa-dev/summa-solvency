#![feature(generic_const_exprs)]
use serde_json::{json, to_writer};
use std::fs;
use summa_backend::{apis::round::Round, tests::initialize_test_env};

const USER_INDEX: usize = 0;

#[tokio::main]
async fn main() {
    // Initialize test environment
    let (anvil, _, _, _, summa_contract, mut address_ownership_client) =
        initialize_test_env().await;

    address_ownership_client
        .dispatch_proof_of_address_ownership()
        .await
        .unwrap();

    // Initialize `Round` for submitting proof of solvency.
    let asset_csv = "src/apis/csv/assets.csv";
    let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
    let params_path = "ptau/hermez-raw-11";

    let mut round = Round::<4, 2, 14>::new(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // anvil account [0]
        anvil.chain_id(),
        anvil.endpoint().as_str(),
        summa_contract.address(),
        entry_csv,
        asset_csv,
        params_path,
        1,
    )
    .unwrap();

    // Before generating inclusion proof, CEX must dispatch proof of solvency for updating the root of merkle sum tree.
    // Without that, the user may not trust your `root_hash` in the inclusion proof because it is not published on-chain.
    round.dispatch_solvency_proof().await.unwrap();

    let inclusion_proof = round.get_proof_of_inclusion(USER_INDEX).unwrap();
    let public_input_vec = inclusion_proof.get_public_inputs();

    let output = json!({
        "proof": serde_json::to_string(&inclusion_proof.get_proof()).unwrap(),
        "leaf_hash": serde_json::to_string(&public_input_vec[0][0]).unwrap(),
        "root_hash": serde_json::to_string(&public_input_vec[0][1]).unwrap()
    });

    let file =
        fs::File::create(format!("user_{}_proof.json", USER_INDEX)).expect("Unable to create file");
    to_writer(file, &output).expect("Failed to write JSON to file");

    println!("Exported proof to user_{}_proof.json", USER_INDEX);
}
