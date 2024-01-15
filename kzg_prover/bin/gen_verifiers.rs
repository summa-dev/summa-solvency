#![feature(generic_const_exprs)]
use halo2_proofs::arithmetic::Field;
use halo2_proofs::{
    halo2curves::bn256::Fr as Fp,
    poly::kzg::{
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::TranscriptWriterBuffer,
};
use halo2_solidity_verifier::{
    compile_solidity, encode_calldata, BatchOpenScheme::Bdfg21, Evm, Keccak256Transcript,
    SolidityGenerator,
};
use num_bigint::BigUint;
use prelude::*;
use rand::rngs::OsRng;
use summa_solvency::{
    circuits::{
        univariate_grand_sum::UnivariateGrandSum,
        utils::{generate_setup_artifacts, open_grand_sums, verify_grand_sum_openings},
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::{big_uint_to_fp, parse_csv_to_entries},
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

fn main() {
    // In order to generate the verifier we create the circuit using the init_empty() method, which means that the circuit is not initialized with any data.
    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();

    let (params, pk, _) =
        generate_setup_artifacts(K, Some("../backend/ptau/hermez-raw-17"), &circuit).unwrap();

    // Only now we can instantiate the circuit with the actual inputs
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

    parse_csv_to_entries::<&str, N_CURRENCIES>("../csv/entry_16.csv", &mut entries, &mut cryptos)
        .unwrap();

    let univariate_grand_sum_circuit =
        UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    // 1. Generate Snark Verifier Contract and Verification Key
    //
    // the instance value is not used in proving, but it is necessary to SolidityGenerator and it should at least 1.
    let num_instance = 1_usize;
    let generator: SolidityGenerator<'_> =
        SolidityGenerator::new(&params, pk.get_vk(), Bdfg21, num_instance);
    let (verifier_solidity, vk_verifier) = generator.render_separately().unwrap();

    let verifier_solidity_fixed = verifier_solidity
        .replace("Halo2Verifier", "Verifier")
        .replace(") public returns (bool)", ") public view returns (bool)");

    let verifier_code = compile_solidity(&verifier_solidity_fixed);
    let vk_code = compile_solidity(&vk_verifier);

    // 2. Generate Snark Proof for range check
    //
    // the instance values has to be at least more than one due to verifier contract that generated from SolidityGenerator.
    let instances: Vec<Fr> = vec![Fp::one(); 1];
    let mut transcript = Keccak256Transcript::new(Vec::new());

    let result = create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
        &params,
        &pk,
        &[univariate_grand_sum_circuit],
        &[&[&instances]],
        &mut OsRng,
        &mut transcript,
    );
    assert!(result.is_ok());

    let result_unwrapped = result.unwrap();
    result_unwrapped.0.expect("prover should not fail");
    let _advice_polys = result_unwrapped.1.clone();
    let advice_polys = _advice_polys[0].clone();

    let _omega = pk.get_vk().get_domain().get_omega();
    let zk_snark_proof = transcript.finalize();

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

    // 3. Deploy Snark Verifier Contract and verify snark proof, which is the Verifier contract
    let mut evm = Evm::default();

    // Calldata for verifying proof on evm
    let vk_address = evm.create(vk_code);
    let proof_calldata = encode_calldata(Some(vk_address.into()), &zk_snark_proof, &instances);

    // Initiate verifier contract
    let verifier_address = evm.create(verifier_code);
    let (_, output) = evm.call(verifier_address, proof_calldata);

    // If successfuly verified, the verifier contract will return 1.
    assert_eq!(output, [vec![0; 31], vec![1]].concat());
    save_solidity("verifier.sol", &verifier_solidity_fixed);
    save_solidity("verifying_key.sol", &vk_verifier);

    // 4. Generate Opening Proof for Grand Sums
    let balance_column_range = 1..N_CURRENCIES + 1;
    let poly_length = 1 << u64::from(K);

    // Calculate total for all entry columns
    let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];
    for entry in &entries {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total[i] += balance;
        }
    }

    let grand_sum_opening_batch_proof = open_grand_sums(
        &advice_polys.advice_polys,
        &advice_polys.advice_blinds,
        &params,
        balance_column_range,
        csv_total
            .iter()
            .map(|x| big_uint_to_fp(x) * Fp::from(poly_length).invert().unwrap())
            .collect::<Vec<Fp>>()
            .as_slice(),
    );

    // The Custodian communicates the polynomial length to the Verifier
    let poly_length = 1 << u64::from(K);

    // Both the Custodian and the Verifier know what column range are the balance columns
    let balance_column_range = 1..N_CURRENCIES + 1;

    let (verified, total_balances) = verify_grand_sum_openings::<N_CURRENCIES>(
        &params,
        &zk_snark_proof,
        &grand_sum_opening_batch_proof,
        poly_length,
        balance_column_range,
    );
    assert!(verified);
    assert_ne!(total_balances, vec![BigUint::from(0u32); N_CURRENCIES]);

    // openining proof contract
    let opening_proof_calldata = encode_calldata(
        Some(vk_address.into()),
        &grand_sum_opening_batch_proof,
        &instances,
    );

    // TODO: fix proof generator, which is `open_grand_sums` to verifiable on the verifier contract.
    let (gas_cost, output) = evm.call(verifier_address, opening_proof_calldata);
    println!(
        "opening_verifier gas_cost: {:?}, and its output: {:?}",
        gas_cost, output
    );
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    const DIR_GENERATED: &str = "./generated";

    create_dir_all(DIR_GENERATED).unwrap();
    File::create(format!("{DIR_GENERATED}/{}", name.as_ref()))
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
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
