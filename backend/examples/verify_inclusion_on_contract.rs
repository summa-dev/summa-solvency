#![feature(generic_const_exprs)]
use std::{error::Error, fs::File, io::BufReader};

use ethers::types::{Bytes, U256};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use serde_json::from_reader;

use summa_backend::{apis::round::Round, tests::initialize_test_env};
mod helpers;
use helpers::inclusion_proof::{generate_leaf_hash, InclusionProof};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Let assume the user can get instance of `summa_contract` and the CEX already submit solvency at timestamp `1`.
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

    // The user will know these constants before or when they receive the proof.
    const N_ASSETS: usize = 2;
    const USER_INDEX: usize = 0;

    let snapshot_time = U256::from(1); // specific time to dispatch solvency proof

    // When verifying the inclusion proof on the user side,-raw-11";
    let proof_path = format!("user_{}_proof.json", USER_INDEX);

    let file = File::open(proof_path)?;
    let reader = BufReader::new(file);
    let proof_data: InclusionProof = from_reader(reader)?;
    let proof: Vec<u8> = serde_json::from_str(&proof_data.proof).unwrap();

    // These `user_name` and `balances` be assumed that are given from the CEX.
    let user_name = "dxGaEAii".to_string();
    let balances = vec![11888, 41163];

    let leaf_hash: Fp = serde_json::from_str(&proof_data.leaf_hash).unwrap();
    assert_eq!(
        leaf_hash,
        generate_leaf_hash::<N_ASSETS>(user_name.clone(), balances.clone())
    );

    // Make public_input from `leaf_hash` and `root_hash` iter and convert it to `Fr`
    let root_hash: Fp = serde_json::from_str(&proof_data.root_hash).unwrap();
    let public_inputs: Vec<U256> = vec![leaf_hash, root_hash]
        .iter()
        .map(|x| {
            let mut bytes = x.to_bytes();
            bytes.reverse();
            U256::from_big_endian(&bytes)
        })
        .collect();

    // Get `mst_root` from contract. the `mst_root` is disptached by CEX with specific time `snapshot_time`.
    let mst_root = summa_contract
        .mst_roots(snapshot_time)
        .call()
        .await
        .unwrap();

    // Compare `mst_root` with `root_hash` from proof.
    assert_eq!(mst_root, public_inputs[1]);

    // Verify inclusion proof on contract verifier
    let verification_result = summa_contract
        .verify_inclusion_proof(Bytes::from(proof), public_inputs, snapshot_time)
        .await
        .unwrap();

    println!(
        "Verifying the proof on contract veirifer for User #{}: {}",
        USER_INDEX, verification_result
    );

    Ok(())
}
