use circuits_halo2::{
    merkle_sum_tree::{MerkleSumTree},
    circuits::utils::{instantiate_empty_circuit, instantiate_circuit, full_prover, full_verifier}
};
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp},
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use rand::rngs::OsRng;


const MAX_POWER: u32 = 10;
const SAMPLE_SIZE: usize = 10;

fn build_mstree_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in 4..=MAX_POWER {
        let num_entries = 2usize.pow(i);
        let csv_file = format!("src/merkle_sum_tree/csv/entry_{}.csv", num_entries);

        let bench_name = format!("build merkle sum tree for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                MerkleSumTree::new(&csv_file).unwrap();
            })
        });
    }
}

// TO DO: replace params with a universal trusted setup
// TO DO: figure out when k has to be increased
fn verification_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);    

    for i in 4..=MAX_POWER {

        let k = 9; // 2^k is the number of rows for the circuit. For a merkle tree in the range between [4 levels (16 entries) and 10 levels (1024), we need 2^9 rows

        // we generate a universal trusted setup of our own for testing
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let bench_name = format!("gen verification key for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                keygen_vk(&params, &instantiate_empty_circuit(i.try_into().unwrap())).expect("vk generation should not fail");
            })
        });
    }
}

// TO DO: replace params with a universal trusted setup
// TO DO: figure out when k has to be increased
fn proving_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);    

    for i in 4..=MAX_POWER {

        let k = 9; // 2^k is the number of rows for the circuit. For a merkle tree in the range between [4 levels (16 entries) and 10 levels (1024), we need 2^9 rows

        // we generate a universal trusted setup of our own for testing
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        let vk = keygen_vk(&params, &instantiate_empty_circuit(i.try_into().unwrap())).expect("vk generation should not fail");
        let bench_name = format!("gen proving key for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                keygen_pk(&params, vk.clone(), &instantiate_empty_circuit(i.try_into().unwrap())).expect("pk generation should not fail");
            })
        });
    }
}

fn generate_zk_proof_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);


    for i in 4..=MAX_POWER {

        let levels = 4;

        let circuit = instantiate_empty_circuit(levels);

        // we generate a universal trusted setup of our own for testing
        let params = ParamsKZG::<Bn256>::setup(9, OsRng);

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let num_entries = 2usize.pow(i);
        let csv_file = format!("src/merkle_sum_tree/csv/entry_{}.csv", num_entries);

        let merkle_sum_tree = MerkleSumTree::new(&csv_file).unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1 in order to make the proof valid

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = instantiate_circuit(assets_sum, mt_proof);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let bench_name = format!("generate zk proof - tree of 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                full_prover(&params, &pk, circuit.clone(), &public_input);
            })
        });
    }
}

fn verify_zk_proof_benchmark(_c: &mut Criterion) {

    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in 4..=MAX_POWER {

        let levels = 4;

        let circuit = instantiate_empty_circuit(levels);

        // we generate a universal trusted setup of our own for testing
        let params = ParamsKZG::<Bn256>::setup(9, OsRng);

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let num_entries = 2usize.pow(i);
        let csv_file = format!("src/merkle_sum_tree/csv/entry_{}.csv", num_entries);

        let merkle_sum_tree = MerkleSumTree::new(&csv_file).unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balance + Fp::from(1u64); // assets_sum are defined as liabilities_sum + 1 in order to make the proof valid

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = instantiate_circuit(assets_sum, mt_proof);

        let public_input = vec![
            circuit.leaf_hash,
            circuit.leaf_balance,
            circuit.root_hash,
            circuit.assets_sum,
        ];

        let proof = full_prover(&params, &pk, circuit, &public_input);

        let bench_name = format!("verify zk proof - tree of 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                full_verifier(&params, &vk, proof.clone(), &public_input);
            })
        });
    }
}

criterion_group!(benches, build_mstree_benchmark, verification_key_gen_benchmark, proving_key_gen_benchmark, generate_zk_proof_benchmark, verify_zk_proof_benchmark);
criterion_main!(benches);
