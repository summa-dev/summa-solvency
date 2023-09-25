#![feature(generic_const_exprs)]
use std::{error::Error, fs::File, io::BufReader, io::Write};

use ethers::{
    abi::{encode, Token},
    types::{Bytes, U256},
    utils::keccak256,
};
use serde_json::{from_reader, to_string_pretty};

use summa_backend::{
    apis::{
        address_ownership::AddressOwnership,
        round::{MstInclusionProof, Round},
    },
    tests::initialize_test_env,
};
use summa_solvency::merkle_sum_tree::utils::generate_leaf_hash;

const N_ASSETS: usize = 2;
const USER_INDEX: usize = 0;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize test environment without `address_ownership` instance from `initialize_test_env` function.
    let (anvil, _, _, _, summa_contract) = initialize_test_env().await;

    // 1. Submit ownership proof
    //
    // Each CEX prepares its own `signature` CSV file.
    let signature_csv_path = "src/apis/csv/signatures.csv";
    let mut address_ownership_client = AddressOwnership::new(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        anvil.chain_id(),
        anvil.endpoint().as_str(),
        summa_contract.address(),
        signature_csv_path,
    )
    .unwrap();

    // Retrieve hashed addresses using the `keccak256` method.
    let address_hashes = address_ownership_client
        .get_ownership_proofs()
        .iter()
        .map(|x| keccak256(encode(&[Token::String(x.cex_address.clone())])))
        .collect::<Vec<[u8; 32]>>();

    // Dispatch the proof of address ownership.
    // the `dispatch_proof_of_address_ownership` function sends a transaction to the Summa contract.
    address_ownership_client
        .dispatch_proof_of_address_ownership()
        .await
        .unwrap();

    // If the `addressHash` isn't found in the `addressOwnershipProofs` mapping of the Summa contract,
    // it will return 0; otherwise, it will return a non-zero value.
    //
    // You can find unregistered address with null bytes as follows:
    //
    // let unregistered = summa_contract
    //     .ownership_proof_by_address([0u8; 32])
    //     .call()
    //     .await
    //     .unwrap();
    //
    // assert_eq!(unregistered, 0);

    // Verify whether the addresses have been registered within the Summa contract.
    for address_hash in address_hashes.iter() {
        let registered = summa_contract
            .ownership_proof_by_address(*address_hash)
            .call()
            .await
            .unwrap();

        assert_ne!(registered, U256::from(0));
    }
    println!("1. Ownership proofs are submitted successfully!");

    // 2. Submit solvency proof
    //
    // Initialize the `Round` instance to submit the proof of solvency.
    let asset_csv = "src/apis/csv/assets.csv";
    let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
    let params_path = "ptau/hermez-raw-11";

    // Using the `round` instance, the solvency proof is dispatched to the Summa contract with the `dispatch_solvency_proof` method.
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

    // Sends the solvency proof, which should ideally complete without errors.
    assert_eq!(round.dispatch_solvency_proof().await.unwrap(), ());

    // You can also use the `solvency_proof_submitted_filter` method to check if the solvency proof is submitted.
    // println!("{:?}", summa_contract
    //     .solvency_proof_submitted_filter()
    //     .query()
    //     .await
    //     .unwrap(););

    println!("2. Solvency proof is submitted successfully!");

    // 3. Generate Inclusion Proof
    //
    // In a production setup, the CEX should first dispatch the solvency proof to update the Merkle sum tree's root before generating any inclusion proofs.
    // Otherwise, users might distrust the provided `root_hash` in the inclusion proof, as it hasn't been published on-chain.
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
    let user_name = "dxGaEAii".to_string();
    let balances = vec![11888, 41163];

    let leaf_hash = public_inputs[0][0];
    assert_eq!(
        leaf_hash,
        generate_leaf_hash::<N_ASSETS>(user_name.clone(), balances.clone())
    );

    // Before verifying `root_hath`, convert type of `proof` and `public_inputs` to the type of `Bytes` and `Vec<U256>`.
    let proof: Bytes = Bytes::from(inclusion_proof.get_proof().clone());
    let public_inputs: Vec<U256> = inclusion_proof
        .get_public_inputs()
        .iter()
        .flat_map(|input_set| {
            input_set.iter().map(|input| {
                let mut bytes = input.to_bytes();
                bytes.reverse();
                U256::from_big_endian(&bytes)
            })
        })
        .collect();

    // Get `mst_root` from contract. the `mst_root` is disptached by CEX with specific time `snapshot_time`.
    let mst_root = summa_contract
        .mst_roots(snapshot_time)
        .call()
        .await
        .unwrap();

    // Match the `mst_root` with the `root_hash` derived from the proof.
    assert_eq!(mst_root, public_inputs[1]);

    // Validate the inclusion proof using the contract verifier.
    let verification_result = summa_contract
        .verify_inclusion_proof(proof, public_inputs, snapshot_time)
        .await
        .unwrap();

    println!(
        "4. Verifying the proof on contract veirifer for User #{}: {}",
        USER_INDEX, verification_result
    );

    Ok(())
}
