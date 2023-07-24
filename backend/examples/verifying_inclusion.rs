use std::fs::File;
use std::io::prelude::*;

use halo2_proofs::halo2curves::{bn256::Fr as Fp, ff::PrimeField};
use num_bigint::BigInt;

use summa_backend::apis::utils::generate_setup_artifacts;
use summa_solvency::{
    circuits::{merkle_sum_tree::MstInclusionCircuit, utils::full_verifier},
    merkle_sum_tree::Entry,
};

fn generate_leaf_hash<const N_ASSETS: usize>(user_name: String, balances: Vec<usize>) -> Fp {
    // Convert usize to BigInt for the `Entry` struct
    let balances_big_int: Vec<BigInt> = balances.into_iter().map(BigInt::from).collect();

    let entry: Entry<N_ASSETS> =
        Entry::new(user_name, balances_big_int.try_into().unwrap()).unwrap();

    entry.compute_leaf().hash
}

fn main() {
    const LEVELS: usize = 4;
    const L: usize = 6;
    const N_ASSETS: usize = 2;

    // When verifying inclusion proof on user side,
    // have to load two files, ptau and proof.
    let ptau_path = "./ptau/hermez-raw-11";

    let mut file = File::open("examples/entry_0_proof.bin").unwrap();
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).unwrap();

    // There are two public inputs, root_hash and leaf hash.
    // the root hash is publicly shared, but leaf hash is not.
    // Only the user can fetch the leaf hash with their name(username) and balances.
    //
    // And the verifier should have access to the username and balances
    //
    // root_hash = 0x02e021d9bf99c5bd7267488b6a7a5cf5f7d00222a41b6a9b971899c44089e0c5
    let root_hash = "1300633067792667740851197998552728163078912135282962223512949070409098715333";

    let proof: Vec<u8> = bincode::deserialize(&encoded[..]).unwrap();

    // Most important thing is that the user should verify the leaf hash using their username and balances.
    let user_name = "dxGaEAii".to_string();
    let balances_usize = vec![11888, 41163];

    // leaf_hash = 0x0e113acd03b98f0bab0ef6f577245d5d008cbcc19ef2dab3608aa4f37f72a407
    let leaf_hash = generate_leaf_hash::<2>(user_name, balances_usize.clone());

    let mst_inclusion_circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();

    let (params, _, vk) = generate_setup_artifacts(ptau_path, 11, mst_inclusion_circuit).unwrap();

    let verification_result: bool = full_verifier(
        &params,
        &vk,
        proof,
        vec![vec![leaf_hash, Fp::from_str_vartime(root_hash).unwrap()]],
    );
    println!("Verification result: {}", verification_result);
}
