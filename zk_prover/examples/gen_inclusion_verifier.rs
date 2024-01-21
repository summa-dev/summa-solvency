#![feature(generic_const_exprs)]

use halo2_proofs::halo2curves::{bn256::Fr as Fp, ff::PrimeField};
use num_bigint::BigInt;
use num_traits::Num;
use prelude::*;

use halo2_solidity_verifier::{compile_solidity, BatchOpenScheme::Bdfg21, SolidityGenerator};
use summa_solvency::circuits::utils::generate_setup_artifacts;
use summa_solvency::circuits::{merkle_sum_tree::MstInclusionCircuit, WithInstances};

const LEVELS: usize = 4;
const N_CURRENCIES: usize = 2;
const N_BYTES: usize = 8;

fn main() {
    // Assert that there is no risk of overflow in the Merkle Root given the combination of `N_BYTES` and `LEVELS`
    assert!(!is_there_risk_of_overflow(N_BYTES, LEVELS), "There is a risk of balance overflow in the Merkle Root, given the combination of `N_BYTES` and `LEVELS`");

    // In order to generate the verifier we create the circuit using the init_empty() method, which means that the circuit is not initialized with any data.
    let circuit = MstInclusionCircuit::<LEVELS, N_CURRENCIES, N_BYTES>::init_empty();

    // generate a universal trusted setup for testing, along with the verification key (vk) and the proving key (pk).
    let (params, pk, _) =
        generate_setup_artifacts(11, Some("../backend/ptau/hermez-raw-11"), circuit.clone())
            .unwrap();

    let num_instances = circuit.num_instances();

    let generator: SolidityGenerator<'_> =
        SolidityGenerator::new(&params, pk.get_vk(), Bdfg21, num_instances);
    let verifier_solidity = generator
        .render()
        .unwrap()
        .replace("Halo2Verifier", "Verifier")
        .replace(") public returns (bool)", ") public view returns (bool)");
    save_solidity("InclusionVerifier.sol", &verifier_solidity);
    let deployment_code = compile_solidity(&verifier_solidity);
    let verifier_creation_code_size = deployment_code.len();
    println!("Verifier creation code size: {verifier_creation_code_size}");
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    const DIR_GENERATED: &str = "../contracts/src";

    create_dir_all(DIR_GENERATED).unwrap();
    let path = format!("{DIR_GENERATED}/{}", name.as_ref());
    File::create(&path)
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
    println!("Saved {path}");
}

// Calculate the maximum value that the Merkle Root can have, given N_BYTES and LEVELS
fn calculate_max_root_balance(n_bytes: usize, n_levels: usize) -> BigInt {
    // The max value that can be stored in a leaf node or a sibling node, according to the constraint set in the circuit
    let max_leaf_value = BigInt::from(2).pow(n_bytes as u32 * 8) - 1;
    max_leaf_value * (n_levels + 1)
}

// Given a combination of `N_BYTES` and `LEVELS`, check if there is a risk of overflow in the Merkle Root
fn is_there_risk_of_overflow(n_bytes: usize, n_levels: usize) -> bool {
    // Calculate the max root balance value
    let max_root_balance = calculate_max_root_balance(n_bytes, n_levels);

    // The modulus of the BN256 curve
    let modulus = BigInt::from_str_radix(&Fp::MODULUS[2..], 16).unwrap();

    // Check if the max balance value is greater than the prime
    max_root_balance > modulus
}

mod prelude {
    pub use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        halo2curves::{
            bn256::{Bn256, Fr, G1Affine},
            ff::PrimeField,
        },
        plonk::*,
        poly::{commitment::Params, kzg::commitment::ParamsKZG, Rotation},
    };
    pub use rand::{
        rngs::{OsRng, StdRng},
        RngCore, SeedableRng,
    };
    pub use std::{
        collections::HashMap,
        fs::{create_dir_all, File},
        io::Write,
        ops::Range,
    };
}
