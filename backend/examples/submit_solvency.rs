#![feature(generic_const_exprs)]
use summa_backend::{apis::round::Round, tests::initialize_test_env};

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

    assert_eq!(round.dispatch_solvency_proof().await.unwrap(), ());

    // You can also use the `solvency_proof_submitted_filter` method to check if the solvency proof is submitted.
    // println!("{:?}", summa_contract
    //     .solvency_proof_submitted_filter()
    //     .query()
    //     .await
    //     .unwrap(););

    println!("Solvency proof is submitted successfully!")
}
