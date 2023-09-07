#![feature(generic_const_exprs)]

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
    merkle_sum_tree::MerkleSumTree,
};

const LEVELS: usize = 4;
const N_ASSETS: usize = 2;
const N_BYTES: usize = 14;

fn main() {
    let merkle_sum_tree =
        MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

    let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS, N_BYTES>::init(merkle_sum_tree, 0);

    // generate a universal trusted setup for testing, along with the verification key (vk) and the proving key (pk).
    let (params, pk, _) =
        generate_setup_artifacts(11, Some("../backend/ptau/hermez-raw-11"), circuit.clone())
            .unwrap();

    let num_instances = circuit.num_instance();
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

    let yul_output_path = "../contracts/src/InclusionVerifier.yul";
    let sol_output_path = "../contracts/src/InclusionVerifier.sol";

    let deployment_code = gen_evm_verifier_shplonk::<MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>>(
        &params,
        pk.get_vk(),
        num_instances,
        Some(Path::new(yul_output_path)),
    );

    write_verifier_sol_from_yul(yul_output_path, sol_output_path).unwrap();

    let gas_cost = evm_verify(deployment_code, instances, proof);

    print!("gas_cost: {:?}", gas_cost);
}
