#![feature(generic_const_exprs)]
use std::{error::Error, fs::File, io::BufReader, io::Write, sync::Arc};

use ethers::{providers::Provider, types::U256};
use serde_json::{from_reader, to_string_pretty};

use summa_backend::{
    apis::{
        address_ownership::AddressOwnership,
        round::{MstInclusionProof, Round},
    },
    contracts::signer::{AddressInput, SummaSigner},
    tests::initialize_test_env,
};
use summa_solvency::merkle_sum_tree::utils::generate_leaf_hash;

const N_ASSETS: usize = 2;
const USER_INDEX: usize = 0;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize test environment without `address_ownership` instance from `initialize_test_env` function.
    let (anvil, _, _, _, summa_contract) = initialize_test_env(None).await;

    // 1. Submit ownership proof
    //
    // Each CEX prepares its own `signature` CSV file.
    let signature_csv_path = "src/apis/csv/signatures.csv";

    // The signer would be using `provider` that shared with `address_ownership` and `round` instances.
    let provider = Arc::new(Provider::try_from(anvil.endpoint().as_str())?);

    // Using AddressInput::Address to directly provide the summa_contract's address.
    // For deployed contracts, if the address is stored in a config file,
    // you can alternatively use AddressInput::Path to specify the file's path.
    let signer = SummaSigner::new(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        anvil.chain_id(),
        provider,
        AddressInput::Address(summa_contract.address()),
    );

    let mut address_ownership_client = AddressOwnership::new(&signer, signature_csv_path).unwrap();

    // Dispatch the proof of address ownership.
    // the `dispatch_proof_of_address_ownership` function sends a transaction to the Summa contract.
    address_ownership_client
        .dispatch_proof_of_address_ownership()
        .await?;

    println!("1. Ownership proofs are submitted successfully!");

    // 2. Submit solvency proof
    //
    // Initialize the `Round` instance to submit the proof of solvency.
    let asset_csv = "src/apis/csv/assets.csv";
    let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
    let params_path = "ptau/hermez-raw-11";

    // Using the `round` instance, the solvency proof is dispatched to the Summa contract with the `dispatch_solvency_proof` method.
    let mut round = Round::<4, 2, 14>::new(&signer, entry_csv, asset_csv, params_path, 1).unwrap();

    // Sends the solvency proof, which should ideally complete without errors.
    round.dispatch_solvency_proof().await?;

    println!("2. Solvency proof is submitted successfully!");

    // 3. Generate Inclusion Proof
    //
    // Generate and export the inclusion proof for the specified user to a JSON file.
    let inclusion_proof = round.get_proof_of_inclusion(USER_INDEX).unwrap();

    let filename = format!("user_{}_proof.json", USER_INDEX);
    let mut file = File::create(filename.clone()).expect("Unable to create file");
    let output = to_string_pretty(&inclusion_proof).unwrap();
    file.write_all(output.as_bytes())
        .expect("Failed to write JSON to file");

    println!(
        "3. Exported proof to user #{}, as `{}`",
        USER_INDEX, filename
    );

    // 4. Verify Inclusion Proof
    //
    // The `snapshot_time` denotes the specific moment when entries were created for the Merkle sum tree.
    // This timestamp is established during the initialization of the Round instance.
    let snapshot_time = U256::from(1);

    // When verifying the inclusion proof from the user's perspective, the user have to fetch `proof`.
    // Assume that the `proof` file has been downloaded from the CEX.
    let proof_file = File::open(format!("user_{}_proof.json", USER_INDEX))?;
    let reader = BufReader::new(proof_file);
    let downloaded_inclusion_proof: MstInclusionProof = from_reader(reader)?;

    let public_inputs = downloaded_inclusion_proof.get_public_inputs();

    // Verify the `leaf_hash` from the proof file.
    // It's assumed that both `user_name` and `balances` are provided by the CEX.
    // The `balances` represent the user's balances on the CEX at `snapshot_time`.
    let user_name = "dxGaEAii".to_string();
    let balances = vec![11888, 41163];

    let leaf_hash = public_inputs[0];
    assert_eq!(
        leaf_hash,
        generate_leaf_hash::<N_ASSETS>(user_name.clone(), balances.clone())
    );

    // Get `mst_root` from contract. the `mst_root` is disptached by CEX with specific time `snapshot_time`.
    let mst_root = summa_contract.mst_roots(snapshot_time).call().await?;

    // Match the `mst_root` with the `root_hash` derived from the proof.
    assert_eq!(mst_root, public_inputs[1]);

    // Validate the inclusion proof using the contract verifier.
    let proof = inclusion_proof.get_proof();
    let verification_result = summa_contract
        .verify_inclusion_proof(proof.clone(), public_inputs.clone(), snapshot_time)
        .await?;

    println!(
        "4. Verifying the proof on contract veirifer for User #{}: {}",
        USER_INDEX, verification_result
    );

    // Wrapping up
    drop(anvil);
    Ok(())
}
