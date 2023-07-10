use std::io::prelude::*;
use std::{fs::File, io::BufReader};

use bincode;
use dialoguer::{Confirm, Input};
use num_bigint::BigInt;
use serde::{Deserialize, Serialize};

use halo2_proofs::{
    halo2curves::{
        bn256::{Fr as Fp, G1Affine},
        ff::PrimeField,
    },
    plonk::VerifyingKey,
    SerdeFormat::RawBytes,
};

use summa_backend::apis::utils;
use summa_solvency::{
    circuits::{merkle_sum_tree::MstInclusionCircuit, utils::full_verifier},
    merkle_sum_tree::Entry,
};

#[derive(Serialize, Deserialize)]
pub struct InclusionProofExport {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
}

fn main() {
    const N_ASSETS: usize = 2;
    const L: usize = 2 + (N_ASSETS * 2);
    const LEVELS: usize = 4;
    const N_BYTES: usize = 64 / 8;
    const K: u32 = 11;

    // Get params from existing ptau file
    let params = utils::get_params(K).unwrap();

    // Currently, we are using vk from the InclusionProofExport from the file.
    //
    // TODO:: check generate vk from the shared pk
    // // Get the path of the proving key file
    // let proving_key_path: String = Input::new()
    //     .with_prompt("Please input the path to the proving key file")
    //     .with_initial_text(&format!(
    //         "artifacts/mst_inclusion_{}_{}_{}.pk",
    //         LEVELS, L, N_ASSETS,
    //     ))
    //     .interact()
    //     .unwrap();

    // // Load the proving key
    // let pk_file = File::open(proving_key_path).unwrap();
    // let mut reader = BufReader::new(pk_file);
    // let pk = ProvingKey::<G1Affine>::read::<_, MstInclusionCircuit<LEVELS, L, N_ASSETS>>(
    //     &mut reader,
    //     RawBytes,
    // )
    // .unwrap();
    // let vk = pk.get_vk();

    // Get the path of the proof file
    let proof_file: String = Input::new()
        .with_prompt("Please input the path to the proof file")
        .with_initial_text("proof.bin")
        .interact()
        .unwrap();

    // Load and deserialize the proof
    let mut file = File::open(proof_file).unwrap();
    let mut encoded = Vec::new();
    file.read_to_end(&mut encoded).unwrap();
    let loaded_proof: InclusionProofExport = bincode::deserialize(&encoded[..]).unwrap();

    // Cursor to read the proof
    let cursor = std::io::Cursor::new(&loaded_proof.vk[..]);
    let mut reader = BufReader::new(cursor);

    // Convert type to VerifyingKey
    let vk = VerifyingKey::<G1Affine>::read::<_, MstInclusionCircuit<LEVELS, L, N_ASSETS>>(
        &mut reader,
        RawBytes,
    )
    .unwrap();

    println!("Initiating verification of `leaf_hash`.");

    // Ask for user details
    let root_hash_str: String = Input::new()
        .with_prompt("Please provide the `root_hash`")
        .interact()
        .unwrap();

    // Convert type from `root_hash_str` to Fp
    let root_hash =
        Fp::from_str_vartime(
            &BigInt::from_bytes_be(num_bigint::Sign::Plus, root_hash_str.as_bytes())
                .to_str_radix(10)[..],
        )
        .unwrap();

    // Ask for user details
    let user_name: String = Input::new()
        .with_prompt("Please provide your `user_name`")
        .interact()
        .unwrap();

    let mut balances_usize = Vec::new();
    for i in 1..=N_ASSETS {
        let balance: usize = Input::new()
            .with_prompt(&format!("Please provide your balance for asset#{}", i))
            .interact()
            .unwrap();
        balances_usize.push(balance);
    }

    let balances_big_int: Vec<BigInt> = balances_usize
        .clone()
        .into_iter()
        .map(|balance| BigInt::from(balance))
        .collect();

    let entry: Entry<N_ASSETS> =
        Entry::new(user_name, balances_big_int.try_into().unwrap()).unwrap();

    let leaf_hash = entry.compute_leaf().hash;

    // Get confirmation from the user
    let proceed = Confirm::new()
        .with_prompt(format!(
            "Your leaf hash is {:?}.\nAre you ready to proceed with the proof verification?",
            leaf_hash
        ))
        .interact()
        .unwrap();

    let verification_result: bool = full_verifier(
        &params,
        &vk,
        loaded_proof.proof,
        vec![vec![leaf_hash], vec![root_hash]],
    );

    if proceed && verification_result {
        // Perform verification
        println!("==========================");
        println!("    mst_root :  \"{}\"", root_hash_str);
        println!("    leaf_hash: \"{:?}\"", leaf_hash);
        println!("    balances : {:?}", balances_usize);
        println!("  ");
        println!("  The proof has been validated");
        println!("==========================");
    } else {
        println!("Proof verification failed.");
    }
}
