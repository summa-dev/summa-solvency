#![feature(generic_const_exprs)]

use halo2_proofs::halo2curves::{bn256::Fr as Fp, ff::PrimeField};
use num_bigint::BigInt;
use num_traits::Num;
use serde_json::to_string_pretty;
use snark_verifier_sdk::{
    evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
    CircuitExt,
};
use std::{fs::File, io::Write, path::Path};
use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        types::ProofSolidityCallData,
        utils::{
            gen_proof_solidity_calldata, generate_setup_artifacts, write_verifier_sol_from_yul,
        },
    },
    merkle_sum_tree::{MerkleSumTree, Tree},
};

const LEVELS: usize = 4;
const N_CURRENCIES: usize = 2;
const N_BYTES: usize = 14;

fn main() {
    // Assert that there is no risk of overflow in the Merkle Root given the combination of `N_BYTES` and `LEVELS`
    assert!(!is_there_risk_of_overflow(N_BYTES, LEVELS), "There is a risk of balance overflow in the Merkle Root, given the combination of `N_BYTES` and `LEVELS`");

    // In order to generate the verifier we create the circuit using the init_empty() method, which means that the circuit is not initialized with any data.
    let circuit = MstInclusionCircuit::<LEVELS, N_CURRENCIES, N_BYTES>::init_empty();

    // generate a universal trusted setup for testing, along with the verification key (vk) and the proving key (pk).
    let (params, pk, _) =
        generate_setup_artifacts(11, Some("../backend/ptau/hermez-raw-11"), circuit.clone())
            .unwrap();

    let num_instances = circuit.num_instance();

    let yul_output_path = "../contracts/src/InclusionVerifier.yul";
    let sol_output_path = "../contracts/src/InclusionVerifier.sol";

    let deployment_code =
        gen_evm_verifier_shplonk::<MstInclusionCircuit<LEVELS, N_CURRENCIES, N_BYTES>>(
            &params,
            pk.get_vk(),
            num_instances,
            Some(Path::new(yul_output_path)),
        );

    write_verifier_sol_from_yul(yul_output_path, sol_output_path).unwrap();

    let merkle_sum_tree =
        MerkleSumTree::<N_CURRENCIES, N_BYTES>::new("../csv/entry_16.csv").unwrap();

    // In order to generate a proof for testing purpose we create the circuit using the init() method
    // which takes as input the merkle sum tree and the index of the leaf we are generating the proof for.

    let user_index = 0;

    let merkle_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

    // Generate the circuit with the actual inputs
    let circuit = MstInclusionCircuit::<LEVELS, N_CURRENCIES, N_BYTES>::init(merkle_proof);

    let instances = circuit.instances();

    let proof = gen_evm_proof_shplonk(&params, &pk, circuit.clone(), instances.clone());

    let proof_solidity_calldata = gen_proof_solidity_calldata(&params, &pk, circuit.clone());

    let proof_hex_string = format!("0x{}", hex::encode(&proof_solidity_calldata.clone().0 .0));

    let data = ProofSolidityCallData {
        proof: proof_hex_string,
        public_inputs: proof_solidity_calldata.1,
    };

    // Serialize the data to a JSON string
    let serialized_data = to_string_pretty(&data).expect("Failed to serialize data");

    // Save the serialized data to a JSON file
    let mut file = File::create("./examples/inclusion_proof_solidity_calldata.json")
        .expect("Unable to create file");
    file.write_all(serialized_data.as_bytes())
        .expect("Unable to write data to file");

    let gas_cost = evm_verify(deployment_code, instances, proof);

    print!("gas_cost: {:?}", gas_cost);
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
