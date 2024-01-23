#![feature(generic_const_exprs)]
use std::{error::Error, fs::File, io::BufReader, io::Write};

use ethers::types::U256;
use serde_json::{from_reader, to_string_pretty};

use summa_backend::{
    apis::{
        address_ownership::AddressOwnership,
        leaf_hash_from_inputs,
        round::{MstInclusionProof, Round},
    },
    contracts::signer::{AddressInput, SummaSigner},
    tests::initialize_test_env,
};
use summa_solvency::merkle_sum_tree::MerkleSumTree;

const N_CURRENCIES: usize = 2;
const USER_INDEX: usize = 0;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize test environment without `address_ownership` instance from `initialize_test_env` function.
    let (anvil, _, _, _, summa_contract) = initialize_test_env(None).await;

    // 1. Submit ownership proof
    //
    // The signer instance would be shared with `address_ownership` and `round` instances
    //
    // Using `AddressInput::Address`` to directly provide the summa_contract's address.
    //
    // If the address of a deployed contract is stored in a configuration file,
    // you can use `AddressInput::Path` to provide the path to that file.
    //
    // For example, if the contract address is in "backend/src/contracts/deployments.json" located
    // you would use `AddressInput::Path` as follows:`AddressInput::Path("backend/src/contracts/deployments.json".to_string())`.
    //
    let signer = SummaSigner::new(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        anvil.endpoint().as_str(),
        AddressInput::Address(summa_contract.address()),
    )
    .await?;

    // Each CEX prepares its own `signature` CSV file.
    let signature_csv_path = "../csv/signatures.csv";
    let mut address_ownership_client = AddressOwnership::new(&signer, signature_csv_path).unwrap();

    // Dispatch the proof of address ownership.
    // the `dispatch_proof_of_address_ownership` function sends a transaction to the Summa contract.
    address_ownership_client
        .dispatch_proof_of_address_ownership()
        .await?;

    println!("1. Ownership proofs are submitted successfully!");

    // 2. Submit Commitment
    //
    // Initialize the `Round` instance to submit the liability commitment.
    let params_path = "ptau/hermez-raw-11";
    let entry_csv = "../csv/entry_16.csv";
    let mst = MerkleSumTree::from_csv(entry_csv).unwrap();

    // Using the `round` instance, the commitment is dispatched to the Summa contract with the `dispatch_commitment` method.
    let timestamp = 1u64;
    let mut round = Round::<4, 2, 8>::new(&signer, Box::new(mst), params_path, timestamp).unwrap();

    // Sends the commitment, which should ideally complete without errors.
    round.dispatch_commitment().await?;

    println!("2. Commitment is submitted successfully!");

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
    let balances = vec!["11888".to_string(), "41163".to_string()];

    let leaf_hash = public_inputs[0];
    assert_eq!(
        leaf_hash,
        leaf_hash_from_inputs::<N_CURRENCIES>(user_name.clone(), balances.clone())
    );

    // Get `mst_root` from contract. the `mst_root` is disptached by CEX with specific time `snapshot_time`.
    let commitment = summa_contract.commitments(snapshot_time).call().await?;

    // Match the `mst_root` with the `root_hash` derived from the proof.
    assert_eq!(commitment, public_inputs[1]);

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
