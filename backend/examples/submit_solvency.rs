#![feature(generic_const_exprs)]
use std::sync::Arc;

use ethers::{types::Address, utils::keccak256};

use summa_backend::{
    apis::{address_ownership::AddressOwnership, round::Round},
    contracts::generated::{solvency_verifier::SolvencyVerifier, summa_contract::Summa},
    tests::initialize_anvil,
};

#[tokio::main]
async fn main() {
    // Initialize test environment
    let (anvil, _, _, client, _) = initialize_anvil().await;

    // In this case, We have to deploy Solvency verifier contract first and then deploy Summa contract.
    let solvency_verifer_contract = SolvencyVerifier::deploy(Arc::clone(&client), ())
        .unwrap()
        .send()
        .await
        .unwrap();

    // We will not use Inclusion verifier contract in this example,
    // so we will set null address for the inclusion verifier contract.
    let summa_contract = Summa::deploy(
        Arc::clone(&client),
        (solvency_verifer_contract.address(), Address::zero()),
    )
    .unwrap()
    .send()
    .await
    .unwrap();

    // Initialize `Solvency` client for submitting proof of solvency.
    // To verify proof of solvency on the contract, at least one ownership address must be registered on the contract.
    let mut address_ownership_client = AddressOwnership::new(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        anvil.chain_id(),
        anvil.endpoint().as_str(),
        summa_contract.address(),
        "src/apis/csv/signatures.csv",
    )
    .unwrap();

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

    round.dispatch_solvency_proof().await.unwrap();

    let log = summa_contract
        .solvency_proof_submitted_filter()
        .query()
        .await
        .unwrap();
    println!("{:?}", log);

    println!("Solvency proof is submitted successfully!")
}
