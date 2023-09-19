#![feature(generic_const_exprs)]
use std::{error::Error, fs::File, io::BufReader};

use halo2_proofs::halo2curves::bn256::Fr as Fp;
use serde_json::from_reader;

use summa_solvency::circuits::{
    merkle_sum_tree::MstInclusionCircuit,
    utils::{full_evm_verifier, generate_setup_artifacts},
};
mod helpers;
use helpers::inclusion_proof::{generate_leaf_hash, InclusionProof};

fn main() -> Result<(), Box<dyn Error>> {
    // This contants should be matched with the constants used while generating the proof.
    const LEVELS: usize = 4;
    const N_ASSETS: usize = 2;
    const N_BYTES: usize = 14;
    const USER_INDEX: usize = 0;

    // When verifying the inclusion proof on local, you have to load two files: `ptau` and `proof`.
    let ptau_path = "./ptau/hermez-raw-11";
    let proof_path = "user_0_proof.json";

    let file = File::open(proof_path)?;
    let reader = BufReader::new(file);
    let proof_data: InclusionProof = from_reader(reader)?;
    let proof: Vec<u8> = serde_json::from_str(&proof_data.proof).unwrap();

    // These `user_name` and `balances` be assumed that are given from the CEX.
    let user_name = "dxGaEAii".to_string();
    let balances_usize = vec![11888, 41163];

    let leaf_hash: Fp = serde_json::from_str(&proof_data.leaf_hash).unwrap();
    assert_eq!(
        leaf_hash,
        generate_leaf_hash::<N_ASSETS>(user_name.clone(), balances_usize.clone())
    );

    let root_hash: Fp = serde_json::from_str(&proof_data.root_hash).unwrap();

    let mst_inclusion_circuit = MstInclusionCircuit::<LEVELS, N_ASSETS, N_BYTES>::init_empty();

    let (params, _, vk) =
        generate_setup_artifacts(11, Some(ptau_path), mst_inclusion_circuit).unwrap();

    let verification_result: bool =
        full_evm_verifier(&params, &vk, proof, vec![vec![leaf_hash, root_hash]]);

    println!(
        "Verifying the proof result for User #{}: {}",
        USER_INDEX, verification_result
    );

    Ok(())
}
