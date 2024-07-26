#![feature(generic_const_exprs)]
use std::{fs::File, io::Write};

use serde_json::to_string_pretty;

use plonkish_backend::{
    backend::{
        hyperplonk::{HyperPlonk, HyperPlonkVerifierParam},
        PlonkishBackend, PlonkishCircuit,
    },
    frontend::halo2::Halo2Circuit,
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::{multilinear::MultilinearKzg, Evaluation, PolynomialCommitmentScheme},
    util::{
        test::seeded_std_rng,
        transcript::{FieldTranscriptRead, InMemoryTranscript, Keccak256Transcript},
    },
};

use summa_backend::{
    apis::round::{KZGProof, Round},
    load_from_file, save_to_file,
};
use summa_hyperplonk::{
    circuits::summa_circuit::summa_hyperplonk::SummaHyperplonk, cryptocurrency::Cryptocurrency,
    entry::Entry, utils::parse_csv_to_entries,
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;
const USER_INDEX: usize = 0;

fn main() {
    type ProvingBackend = HyperPlonk<MultilinearKzg<Bn256>>;

    // 1. Generate Commitment
    //
    // Initialize the `Round` instance to generate the commitment and verifier parameters.
    let entry_csv = "../csv/entry_16.csv";
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
    parse_csv_to_entries::<&str, N_CURRENCIES>(entry_csv, &mut entries, &mut cryptos).unwrap();

    let circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init(entries.to_vec());
    let num_vars = K;

    let circuit_fn = |num_vars, initialized_circuit| {
        let circuit = Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<
            ProvingBackend,
        >(num_vars, initialized_circuit);
        (circuit.circuit_info().unwrap(), circuit)
    };

    let (circuit_info, circuit) = circuit_fn(num_vars as usize, circuit);
    let instances = circuit.instances();

    let param = ProvingBackend::setup_custom("../backend/ptau/hyperplonk-srs-17").unwrap();
    let (pp, vp) = ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let (advice_polys, proof_transcript) = {
        let mut proof_transcript = Keccak256Transcript::new(());

        let advice_polys =
            ProvingBackend::prove(&pp, &circuit, &mut proof_transcript, seeded_std_rng()).unwrap();
        (advice_polys, proof_transcript)
    };

    let zk_snark_proof = proof_transcript.into_proof();

    // Simple check of the proof before initializing the `Round` instance.
    let mut transcript;
    let result: Result<(), plonkish_backend::Error> = {
        transcript = Keccak256Transcript::from_proof((), zk_snark_proof.as_slice());
        ProvingBackend::verify(&vp, instances, &mut transcript, seeded_std_rng())
    };
    assert_eq!(result, Ok(()));

    // Using the `round` instance, the custodian can get commitment proof and verifier params.
    let snapshot_time = 1u64;
    let mut round = Round::<N_CURRENCIES, N_USERS>::new(
        zk_snark_proof.clone(),
        advice_polys,
        pp,
        vp.clone(),
        snapshot_time,
    );

    // The commitment and verifier parameters should be publicly available to all users.
    let (zk_proof, vp) = round.gen_commitment_and_vp().unwrap();

    let vp_filename = "verifier_params.json";
    let _ = save_to_file::<_, HyperPlonkVerifierParam<Fp, MultilinearKzg<Bn256>>>(vp_filename, &vp);

    let commitment_proof_filename = "commitment_proof.json";
    let _ = save_to_file::<_, KZGProof>(commitment_proof_filename, &zk_proof);

    println!("1. Commitment and Verifier Parameters successfully Exported!");

    // 2. Generate Inclusion Proof
    //
    // Generate then export the inclusion proof for the specified user to a JSON file.
    let inclusion_proof = round.get_proof_of_inclusion(USER_INDEX).unwrap();

    let proof_filename = format!("user_{}_proof.json", USER_INDEX);
    let mut file = File::create(proof_filename.clone()).expect("Unable to create inclusion file");
    let output = to_string_pretty(&inclusion_proof).unwrap();
    file.write_all(output.as_bytes())
        .expect("Failed to write inclusion proof to a JSON file");

    let _ = save_to_file("user_proof.json", &inclusion_proof);

    println!(
        "2. Exported proof to user #{}, as `{}`, with verifier params `{}`",
        USER_INDEX, proof_filename, vp_filename
    );

    // 3. Verify Inclusion Proof
    //
    // Users can generate verifier parameters using only the configurations for "N_CURRENCIES" and "N_USERS", along with the SRS.
    let dummy_circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init_empty();

    let (circuit_info, _) = circuit_fn(num_vars as usize, dummy_circuit);

    let param = ProvingBackend::setup_custom("../backend/ptau/hyperplonk-srs-17").unwrap();
    let (_, verifier_params) = ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let loaded_verifier_params: HyperPlonkVerifierParam<Fp, MultilinearKzg<Bn256>> =
        load_from_file(vp_filename).unwrap();

    // Load the commitment from the files
    let commitment: KZGProof = load_from_file(commitment_proof_filename).unwrap();

    // When verifying the inclusion proof from the user's perspective, the user have to fetch `proof`.
    // Assume that the `proof` file has been downloaded from the CEX along with commitment and verifier parameters.
    let proof: KZGProof = load_from_file(format!("user_{}_proof.json", USER_INDEX))
        .expect("Failed to load proof from JSON file");

    // Load commitment from the commitment file
    let mut transcript = Keccak256Transcript::from_proof((), commitment.get_proof().as_slice());
    let user_entry_commitments = MultilinearKzg::<Bn256>::read_commitments(
        &verifier_params.pcs,
        N_CURRENCIES + 1,
        &mut transcript,
    )
    .unwrap();

    let mut kzg_transcript = Keccak256Transcript::from_proof((), proof.get_proof().as_slice());
    let mut multivariate_challenge: Vec<Fp> = Vec::new();
    for _ in 0..num_vars {
        multivariate_challenge.push(kzg_transcript.read_field_element().unwrap());
    }

    let input_values = proof.get_input_values();
    let evals: Vec<Evaluation<Fp>> = (0..N_CURRENCIES + 1)
        .map(|i| Evaluation::new(i, 0, input_values[i]))
        .collect();

    MultilinearKzg::<Bn256>::batch_verify(
        &verifier_params.pcs,
        &user_entry_commitments,
        &[multivariate_challenge.clone()],
        &evals,
        &mut kzg_transcript,
    )
    .unwrap();

    println!(
        "3. Verified the proof with veirifer parameters for User #{}",
        USER_INDEX
    );
}
