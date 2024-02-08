#![feature(generic_const_exprs)]
use halo2_proofs::{
    halo2curves::bn256::Fr as Fp,
    poly::kzg::{multiopen::VerifierSHPLONK, strategy::SingleStrategy},
};
use halo2_solidity_verifier::{compile_solidity, encode_calldata, Evm, Keccak256Transcript};
use prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use summa_solvency::circuits::{
    univariate_grand_sum::UnivariateGrandSum, utils::generate_setup_artifacts,
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

#[derive(Serialize, Deserialize)]
struct CommitmentSolidityCallData {
    range_check_snark_proof: String,
    grand_sums_batch_proof: String,
}

fn main() {
    // In order to generate the verifier we create the circuit using the init_empty() method, which means that the circuit is not initialized with any data.
    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();

    let (params, pk, _) =
        generate_setup_artifacts(K, Some("../backend/ptau/hermez-raw-17"), &circuit).unwrap();
    // let omega = pk.get_vk().get_domain().get_omega();

    // Read `commitment_solidity_calldata.json` and parse it to `CommitmentSolidityCallData`
    let commitment_solidity_calldata = read_to_string("./bin/commitment_solidity_calldata.json")
        .expect("commitment_solidity_calldata.json not found");
    let commitment_solidity_calldata: CommitmentSolidityCallData =
        serde_json::from_str(&commitment_solidity_calldata).unwrap();

    // String to Vec<u8> with stripe 0x prefix
    let zk_snark_proof = hex::decode(&commitment_solidity_calldata.range_check_snark_proof[2..])
        .expect("Invalid zk_snark_proof from string");
    let instances: Vec<Fr> = vec![Fp::one(); 1];

    // Check verification on verifier function
    let verified = {
        let mut transcript = Keccak256Transcript::new(zk_snark_proof.as_slice());
        verify_proof::<_, VerifierSHPLONK<_>, _, _, _>(
            &params,
            pk.get_vk(),
            SingleStrategy::new(&params),
            &[&[&instances]],
            &mut transcript,
        )
    };
    assert!(verified.is_ok());

    let mut evm = Evm::default();

    // Calldata for verifying proof on evm
    let vk_code_string = read_to_string("./generated/verifying_key.sol").unwrap();
    let vk_code = compile_solidity(vk_code_string);
    let vk_address = evm.create(vk_code);

    // 3. Deploy Snark Verifier Contract and verify snark proof
    let grand_sum_opening_batch_proof =
        hex::decode(&commitment_solidity_calldata.grand_sums_batch_proof[2..]).unwrap();

    // TODO: implement generate solidity for opening grandsum verifier
    // this is temporary solidity code for opening grandsum verifier
    let opening_grandsum_verifier_solidity =
        read_to_string("./generated/kzg_verifier.sol").unwrap();

    // Deploy opening verifier contract
    let opening_grandsum_verifier_code = compile_solidity(opening_grandsum_verifier_solidity);
    let opening_grandsum_verifier_address = evm.create(opening_grandsum_verifier_code);

    // Combine `zk_snark_proof` and `grand_sum_opening_batch_proof`.
    // The first 64 bytes(one point) is not for verifying grand sum proof, skip it.
    // And then slice the `grand_sum_opening_batch_proof` length from `zk_snark_proof`.
    let commitments_points =
        zk_snark_proof[64..(64 + grand_sum_opening_batch_proof.len())].to_vec();

    let grand_sum_verifier_inputs =
        [grand_sum_opening_batch_proof.clone(), commitments_points].concat();

    // Openining proof contract
    // Unlikely in snark verifier, the instance is being used as input values not actual instance in the kzg verifier contract.
    let values = vec![Fp::from(556862), Fp::from(556862)];
    let opening_grandsum_proof_calldata =
        encode_calldata(Some(vk_address.into()), &grand_sum_verifier_inputs, &values);

    let (gas_cost, output) = evm.call(
        opening_grandsum_verifier_address,
        opening_grandsum_proof_calldata,
    );

    assert_eq!(output, [vec![0; 31], vec![1]].concat());
    println!("opening grand sum verifying gas cost: {:?}", gas_cost);
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
