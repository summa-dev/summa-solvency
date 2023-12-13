#![feature(generic_const_exprs)]
use prelude::*;

use halo2_solidity_verifier::{
    compile_solidity, encode_calldata, BatchOpenScheme::Bdfg21, Evm, Keccak256Transcript,
    SolidityGenerator,
};
use summa_solvency::{
    circuits::univariate_grand_sum::UnivariateGrandSum, cryptocurrency::Cryptocurrency,
    entry::Entry, utils::parse_csv_to_entries,
};

const K: u32 = 17;

const N_BYTES: usize = 8;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

fn main() {
    println!("Generating setup parameters...");
    let mut rng = seeded_std_rng();

    let params = ParamsKZG::<Bn256>::setup(K, &mut rng);
    println!("Setup parameters generated");

    let path = "src/csv/entry_16.csv";

    println!("Parsing CSV...");
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

    parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(path, &mut entries, &mut cryptos).unwrap();
    println!("CSV parsed");
    println!("Instantiating the circuit...");
    let circuit = UnivariateGrandSum::<N_BYTES, N_USERS, N_CURRENCIES>::init(entries.to_vec());

    let vk = keygen_vk(&params, &circuit).unwrap();
    let generator = SolidityGenerator::new(&params, &vk, Bdfg21, 0);
    let (verifier_solidity, _) = generator.render_separately().unwrap();
    save_solidity("Halo2Verifier.sol", &verifier_solidity);

    let verifier_creation_code = compile_solidity(&verifier_solidity);
    let verifier_creation_code_size = verifier_creation_code.len();
    println!("Verifier creation code size: {verifier_creation_code_size}");

    let mut evm = Evm::default();
    let verifier_address = evm.create(verifier_creation_code);

    let deployed_verifier_solidity = verifier_solidity;

    let vk = keygen_vk(&params, &circuit.clone()).unwrap();
    let pk = keygen_pk(&params, vk, &circuit).unwrap();
    let generator = SolidityGenerator::new(&params, pk.get_vk(), Bdfg21, 0);
    let (verifier_solidity, vk_solidity) = generator.render_separately().unwrap();
    save_solidity(format!("Halo2VerifyingKey-{K}.sol"), &vk_solidity);

    assert_eq!(deployed_verifier_solidity, verifier_solidity);

    let vk_creation_code = compile_solidity(&vk_solidity);
    let vk_address = evm.create(vk_creation_code);

    println!("Encoding calldata...");
    let calldata = {
        let instances = [];
        let proof = create_proof_checked(&params, &pk, circuit, &instances, &mut rng);
        encode_calldata(Some(vk_address.into()), &proof, &instances)
    };
    println!("Calldata encoded");
    let (gas_cost, output) = evm.call(verifier_address, calldata);
    assert_eq!(output, [vec![0; 31], vec![1]].concat());
    println!("Gas cost of verifying Summa with 2^{K} rows: {gas_cost}");
}

fn save_solidity(name: impl AsRef<str>, solidity: &str) {
    const DIR_GENERATED: &str = "./generated";

    create_dir_all(DIR_GENERATED).unwrap();
    let path = format!("{DIR_GENERATED}/{}", name.as_ref());
    File::create(&path)
        .unwrap()
        .write_all(solidity.as_bytes())
        .unwrap();
    println!("Saved {path}");
}

fn create_proof_checked(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: impl Circuit<Fr>,
    instances: &[Fr],
    mut rng: impl RngCore,
) -> Vec<u8> {
    use halo2_proofs::{
        poly::kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
        transcript::TranscriptWriterBuffer,
    };

    println!("Creating proof...");

    let proof = {
        let mut transcript = Keccak256Transcript::new(Vec::new());
        let proof_creation_result = create_proof::<_, ProverSHPLONK<_>, _, _, _, _>(
            params,
            pk,
            &[circuit],
            &[&[instances]],
            &mut rng,
            &mut transcript,
        );
        assert!(proof_creation_result.is_ok());
        transcript.finalize()
    };

    let result = {
        let mut transcript = Keccak256Transcript::new(proof.as_slice());
        verify_proof::<_, VerifierSHPLONK<_>, _, _, SingleStrategy<_>>(
            params,
            pk.get_vk(),
            SingleStrategy::new(params),
            &[&[instances]],
            &mut transcript,
        )
    };
    assert!(result.is_ok());

    println!("Proof created and verified");

    proof
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

    pub fn seeded_std_rng() -> impl RngCore {
        StdRng::seed_from_u64(OsRng.next_u64())
    }
}
