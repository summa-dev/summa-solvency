#![feature(generic_const_exprs)]

use ethers::abi::parse_abi;
use ethers::abi::Token::{Array, Bytes, Uint};
use halo2_solidity_verifier::{compile_solidity, BatchOpenScheme::Bdfg21, Evm, SolidityGenerator};
use serde_json::to_string_pretty;
use std::{fs::File, io::Write};
use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        types::ProofSolidityCallData,
        utils::{gen_proof_solidity_calldata, generate_setup_artifacts},
        WithInstances,
    },
    merkle_sum_tree::{MerkleSumTree, Tree},
};

const LEVELS: usize = 4;
const N_CURRENCIES: usize = 2;
const N_BYTES: usize = 8;

fn main() {
    let merkle_sum_tree =
        MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

    // In order to generate a proof for testing purpose we create the circuit using the init() method
    // which takes as input the merkle sum tree and the index of the leaf we are generating the proof for.
    let user_index = 0;

    let merkle_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

    // Generate the circuit with the actual inputs
    let circuit = MstInclusionCircuit::<LEVELS, N_CURRENCIES, N_BYTES>::init(merkle_proof);

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
        .replace("Halo2Verifier", "Verifier");
    let deployment_code = compile_solidity(&verifier_solidity);

    let proof_solidity_calldata = gen_proof_solidity_calldata(&params, &pk, circuit.clone());

    let proof_hex_string = format!("0x{}", hex::encode(&proof_solidity_calldata.clone().0 .0));

    let calldata_instances = proof_solidity_calldata.1.clone();

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

    let abi = parse_abi(&[
        "function verifyProof(bytes calldata proof, uint256[] calldata instances) public returns (bool)",
    ]).expect("Invalid ABI");

    let function = abi.function("verifyProof").unwrap();
    let calldata_encoded = function
        .encode_input(&[
            Bytes(proof_solidity_calldata.0.to_vec()),
            Array(
                calldata_instances
                    .iter()
                    .map(|&instance| Uint(instance))
                    .collect(),
            ),
        ])
        .unwrap();

    let mut evm = Evm::default();
    let verifier_address = evm.create(deployment_code);

    let (gas_cost, output) = evm.call(verifier_address, calldata_encoded);
    assert_eq!(output, [vec![0; 31], vec![1]].concat());
    println!("gas_cost: {:?}", gas_cost);
}
