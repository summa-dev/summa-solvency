#![feature(generic_const_exprs)]
use ethers::types::U256;
use halo2_proofs::{
    arithmetic::Field,
    halo2curves::{
        bn256::{Bn256, Fr as Fp},
        group::Curve,
    },
    poly::kzg::commitment::KZGCommitmentScheme,
};
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::{fs::File, io::Write};

use summa_solvency::{
    circuits::{
        univariate_grand_sum::UnivariateGrandSum,
        utils::{full_prover, full_verifier, generate_setup_artifacts},
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::{
        amortized_kzg::{commit_kzg, create_naive_kzg_proof, verify_kzg_proof},
        big_uint_to_fp, parse_csv_to_entries,
    },
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

#[derive(Serialize, Deserialize)]
struct InclusionProofCallData {
    proof: String,
    challenge: U256,
    username: String,
    balances: Vec<U256>,
}

fn main() {
    // Initialize with entries
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

    parse_csv_to_entries::<&str, N_CURRENCIES>("../csv/entry_16.csv", &mut entries, &mut cryptos)
        .unwrap();

    let univariate_grand_sum_circuit =
        UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    let (params, pk, vk) = generate_setup_artifacts(
        K,
        Some("../backend/ptau/hermez-raw-17"),
        &univariate_grand_sum_circuit,
    )
    .unwrap();

    // Create a snark proof
    let (zk_snark_proof, advice_polys, omega) = full_prover(
        &params,
        &pk,
        univariate_grand_sum_circuit.clone(),
        &[vec![]],
    );
    assert!(full_verifier(&params, &vk, &zk_snark_proof, &[vec![]]));

    // For testing purposes, we will open the user balances and generate a proof for the user at index 2.
    let user_index = 2_u16;
    let challenge = omega.pow_vartime([user_index as u64]);

    let user_values = &entries
        .get(user_index as usize)
        .map(|entry| {
            std::iter::once(big_uint_to_fp(&(entry.username_as_big_uint())))
                .chain(entry.balances().iter().map(|x| big_uint_to_fp(x)))
                .collect::<Vec<Fp>>()
        })
        .unwrap();

    let column_range = 0..N_CURRENCIES + 1;
    let mut inclusion_proof: Vec<Vec<u8>> = Vec::new();
    for column_index in column_range {
        let f_poly = advice_polys.advice_polys.get(column_index).unwrap();
        let kzg_commitment = commit_kzg(&params, f_poly);

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
            verify_kzg_proof(&params, kzg_commitment, kzg_proof, &challenge, &z,),
            "KZG proof verification failed for user {}",
            user_index
        );

        // Convert to affine point and serialize to bytes
        let kzg_proof_affine = kzg_proof.to_affine();
        let mut kzg_proof_affine_x = kzg_proof_affine.x.to_bytes();
        let mut kzg_proof_affine_y = kzg_proof_affine.y.to_bytes();
        kzg_proof_affine_x.reverse();
        kzg_proof_affine_y.reverse();

        // concat x, y of kzg_proof
        inclusion_proof.push([kzg_proof_affine_x, kzg_proof_affine_y].concat());
    }

    let proof_hex_string = format!("0x{}", hex::encode(inclusion_proof.concat()));
    let username = entries[user_index as usize].username().to_string();
    let user_values = user_values
        .iter()
        .map(|x| U256::from_little_endian(x.to_bytes().as_slice()))
        .collect::<Vec<U256>>();

    let neg_challenge = challenge.neg();
    let data = InclusionProofCallData {
        proof: proof_hex_string,
        username,
        challenge: U256::from_little_endian(neg_challenge.to_bytes().as_slice()),
        balances: user_values,
    };

    let serialized_data = to_string_pretty(&data).expect("Failed to serialize data");

    // Save the serialized data to a JSON file
    let mut file = File::create("./bin/inclusion_proof_solidity_calldata.json")
        .expect("Unable to create file");
    file.write_all(serialized_data.as_bytes())
        .expect("Unable to write data to file");
}
