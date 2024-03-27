#![feature(generic_const_exprs)]
use ethers::types::U256;
use halo2_proofs::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine, G2Affine},
        group::{cofactor::CofactorCurveAffine, Curve},
    },
    poly::kzg::commitment::KZGCommitmentScheme,
    transcript::TranscriptRead,
};
use halo2_solidity_verifier::Keccak256Transcript;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::{fs::File, io::Write};
use summa_solvency::{
    circuits::{
        univariate_grand_sum::{UnivariateGrandSum, UnivariateGrandSumConfig},
        utils::{full_prover, full_verifier, generate_setup_artifacts},
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::{
        amortized_kzg::{create_naive_kzg_proof, verify_kzg_proof},
        big_uint_to_fp, parse_csv_to_entries,
    },
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

#[derive(Serialize, Deserialize)]
struct CommitmentSolidityCallData {
    range_check_snark_proof: String,
    grand_sums_batch_proof: String,
    total_balances: Vec<U256>,
}

#[derive(Serialize, Deserialize)]
struct InclusionProofCallData {
    proof: String,
    challenges: Vec<U256>,
    user_id: String,
    user_values: Vec<U256>,
}

fn main() {
    // Initialize with entries
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

    // Parse CSV to update entries and cryptos arrays
    parse_csv_to_entries::<&str, N_CURRENCIES>("../csv/entry_16.csv", &mut entries, &mut cryptos)
        .unwrap();

    let univariate_grand_sum_circuit = UnivariateGrandSum::<
        N_USERS,
        N_CURRENCIES,
        UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
    >::init(entries.to_vec());

    let (params, pk, _) = generate_setup_artifacts(
        K,
        Some("../backend/ptau/hermez-raw-17"),
        &univariate_grand_sum_circuit,
    )
    .unwrap();

    // Create a proof
    let instances = vec![Fp::zero(); 1]; // This instance is necessary to verify proof on solidity verifier.
    let (zk_snark_proof, advice_polys, omega) = full_prover(
        &params,
        &pk,
        univariate_grand_sum_circuit.clone(),
        &[instances.clone()],
    );

    // Verify the proof to ensure validity
    assert!(full_verifier(
        &params,
        pk.get_vk(),
        &zk_snark_proof,
        &[instances]
    ));

    let challenge = Fp::zero();
    let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];
    for entry in &entries {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total[i] += balance;
        }
    }

    // Evaluate the commitments from the snark proof
    let mut kzg_commitments = Vec::with_capacity(N_CURRENCIES);
    let mut transcript = Keccak256Transcript::new(zk_snark_proof.as_slice());
    for _ in 0..(N_CURRENCIES + 1) {
        let point: G1Affine = transcript.read_point().unwrap();
        kzg_commitments.push(point.to_curve());
    }

    let poly_length = 1 << u64::from(K);
    let total_balances = csv_total
        .iter()
        .map(|x| big_uint_to_fp(x) * Fp::from(poly_length).invert().unwrap())
        .collect::<Vec<Fp>>();

    let mut grand_sums_kzg_proof = Vec::new();
    for balance_column in 1..(N_CURRENCIES + 1) {
        let f_poly = advice_polys.advice_polys.get(balance_column).unwrap();

        let currency_index = balance_column - 1;
        let kzg_proof = create_naive_kzg_proof::<KZGCommitmentScheme<Bn256>>(
            &params,
            pk.get_vk().get_domain(),
            f_poly,
            challenge,
            total_balances[currency_index],
        );

        // Ensure the KZG proof is valid
        assert!(verify_kzg_proof(
            &params,
            kzg_commitments[balance_column],
            kzg_proof,
            &challenge,
            &total_balances[currency_index],
        ));

        // Convert to affine point and serialize to bytes
        let kzg_proof_affine = kzg_proof.to_affine();
        let mut kzg_proof_affine_x = kzg_proof_affine.x.to_bytes();
        let mut kzg_proof_affine_y = kzg_proof_affine.y.to_bytes();
        kzg_proof_affine_x.reverse();
        kzg_proof_affine_y.reverse();

        // Concatenate x and y of the KZG proof
        grand_sums_kzg_proof.push([kzg_proof_affine_x, kzg_proof_affine_y].concat());
    }

    let commitment = CommitmentSolidityCallData {
        range_check_snark_proof: format!("0x{}", hex::encode(zk_snark_proof)),
        grand_sums_batch_proof: format!("0x{}", hex::encode(grand_sums_kzg_proof.concat())),
        total_balances: csv_total
            .iter()
            .map(|x| U256::from_little_endian(big_uint_to_fp(x).to_bytes().as_slice()))
            .collect::<Vec<U256>>(),
    };

    // Serialize the data for solidity
    let serialized_data = to_string_pretty(&commitment).expect("Failed to serialize data");

    // Save the serialized data to a JSON file
    let mut file =
        File::create("./bin/commitment_solidity_calldata.json").expect("Unable to create file");
    file.write_all(serialized_data.as_bytes())
        .expect("Unable to write data to file");

    // For testing, open user balances and generate a proof for a specific user index
    let user_index = 1_u16; // Example user index for proof generation
    let challenge = omega.pow_vartime([user_index as u64]);

    let user_values = &entries
        .get(user_index as usize)
        .map(|entry| {
            std::iter::once(big_uint_to_fp(entry.username_as_big_uint()))
                .chain(entry.balances().iter().map(big_uint_to_fp))
                .collect::<Vec<Fp>>()
        })
        .unwrap();

    let column_range = 0..N_CURRENCIES + 1;
    let mut inclusion_proof: Vec<Vec<u8>> = Vec::new();
    for column_index in column_range {
        let f_poly = advice_polys.advice_polys.get(column_index).unwrap();

        let z = if column_index == 0 {
            big_uint_to_fp(entries[user_index as usize].username_as_big_uint())
        } else {
            big_uint_to_fp(&entries[user_index as usize].balances()[column_index - 1])
        };

        let kzg_proof = create_naive_kzg_proof::<KZGCommitmentScheme<Bn256>>(
            &params,
            pk.get_vk().get_domain(),
            f_poly,
            challenge,
            z,
        );

        assert!(
            verify_kzg_proof(
                &params,
                kzg_commitments[column_index],
                kzg_proof,
                &challenge,
                &z,
            ),
            "KZG proof verification failed for user {}",
            user_index
        );

        // Convert to affine point and serialize to bytes
        let kzg_proof_affine = kzg_proof.to_affine();
        let mut kzg_proof_affine_x = kzg_proof_affine.x.to_bytes();
        let mut kzg_proof_affine_y = kzg_proof_affine.y.to_bytes();
        kzg_proof_affine_x.reverse();
        kzg_proof_affine_y.reverse();

        // Concat x, y of kzg_proof
        inclusion_proof.push([kzg_proof_affine_x, kzg_proof_affine_y].concat());
    }

    let user_values = user_values
        .iter()
        .map(|x| U256::from_little_endian(x.to_bytes().as_slice()))
        .collect::<Vec<U256>>();

    // Evaluate S_G2 points with challenge for verifying proof on the KZG solidity verifier
    let s_g2 = -params.s_g2() + (G2Affine::generator() * challenge);
    let s_g2_affine = s_g2.to_affine();

    let challenges = vec![
        U256::from_little_endian(s_g2_affine.x.c1.to_bytes().as_slice()),
        U256::from_little_endian(s_g2_affine.x.c0.to_bytes().as_slice()),
        U256::from_little_endian(s_g2_affine.y.c1.to_bytes().as_slice()),
        U256::from_little_endian(s_g2_affine.y.c0.to_bytes().as_slice()),
    ];

    let data = InclusionProofCallData {
        proof: format!("0x{}", hex::encode(inclusion_proof.concat())),
        user_id: entries[user_index as usize].username().to_string(),
        challenges,
        user_values,
    };

    let serialized_data = to_string_pretty(&data).expect("Failed to serialize data");

    // Save the serialized data to a JSON file
    let mut file = File::create("./bin/inclusion_proof_solidity_calldata.json")
        .expect("Unable to create file");
    file.write_all(serialized_data.as_bytes())
        .expect("Unable to write data to file");
}
