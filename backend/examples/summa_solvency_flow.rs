#![feature(generic_const_exprs)]
use std::{error::Error, fs::File, io::BufReader, io::Write};

use ethers::types::U256;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use serde_json::{from_reader, to_string_pretty};

use summa_backend::{
    apis::{
        address_ownership::AddressOwnership,
        round::{KZGProof, Round},
    },
    contracts::signer::{AddressInput, SummaSigner},
    tests::initialize_test_env,
};
use summa_solvency::{
    circuits::{
        univariate_grand_sum::{UnivariateGrandSum, UnivariateGrandSumConfig},
        utils::{full_prover, generate_setup_artifacts},
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::parse_csv_to_entries,
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;
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
    let entry_csv = "../csv/entry_16.csv";
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
    parse_csv_to_entries::<&str, N_CURRENCIES>(entry_csv, &mut entries, &mut cryptos).unwrap();

    let univariate_grand_sum_circuit = UnivariateGrandSum::<
        N_USERS,
        N_CURRENCIES,
        UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
    >::init(entries.to_vec());

    // This ptau file is also utilized in the generation of the verifier contract.
    // It corresponds to the same file used in the `gen_verifier.rs` script.
    let params_path = "../backend/ptau/hermez-raw-17";
    let (params, pk, vk) =
        generate_setup_artifacts(K, Some(params_path), &univariate_grand_sum_circuit).unwrap();

    // Create a proof
    let instances = vec![Fp::zero(); 1]; // This instance is necessary to verify proof on solidity verifier.
    let (zk_snark_proof, advice_polys, _) = full_prover(
        &params,
        &pk,
        univariate_grand_sum_circuit.clone(),
        &[instances.clone()],
    );

    // Using the `round` instance, the commitment is dispatched to the Summa contract with the `dispatch_commitment` method.
    let timestamp = 1u64;
    let mut round = Round::<N_CURRENCIES, N_USERS>::new(
        &signer,
        zk_snark_proof,
        advice_polys,
        params,
        vk,
        timestamp,
    );

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
    // The `snapshot_time` denotes the specific moment when entries were created for polynomal interpolation.
    // This timestamp is established during the initialization of the Round instance.
    let snapshot_time = U256::from(timestamp);

    // When verifying the inclusion proof from the user's perspective, the user have to fetch `proof`.
    // Assume that the `proof` file has been downloaded from the CEX.
    let proof_file = File::open(format!("user_{}_proof.json", USER_INDEX))?;
    let reader = BufReader::new(proof_file);

    let downloaded_inclusion_proof: KZGProof = from_reader(reader)?;

    // Fetch commitment data from the contract with timestamp, `snapshot_time`.
    let commitment = summa_contract.commitments(snapshot_time).call().await?;

    // Ensure the length of the commitment matches the expected size for the number of points.
    assert_eq!(commitment.to_vec().len(), 0x40 * (N_CURRENCIES + 1));

    // Validate the inclusion proof using the contract verifier.
    let mut verification_result = false;

    if let Some(challenges) = downloaded_inclusion_proof.get_challenge().as_ref() {
        verification_result = summa_contract
            .verify_inclusion_proof(
                snapshot_time,
                inclusion_proof.get_proof().clone(),
                challenges.clone(),
                inclusion_proof.get_input_values().clone(),
            )
            .await?;
    } else {
        eprintln!("No challenges found in the proof, This may not a inclusion proof");
    }

    println!(
        "4. Verifying the proof on contract veirifer for User #{}: {}",
        USER_INDEX, verification_result
    );

    // Wrapping up
    drop(anvil);
    Ok(())
}
