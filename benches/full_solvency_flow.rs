use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp},
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use std::convert::TryInto;
use summa_solvency::{
    circuits::merkle_sum_tree::MerkleSumTreeCircuit,
    circuits::utils::{full_prover, full_verifier, generate_setup_params},
    merkle_sum_tree::MerkleSumTree,
};

const MIN_POWER: u32 = 5;
const MAX_POWER: u32 = 6;
const SAMPLE_SIZE: usize = 10;

fn build_mstree_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in MIN_POWER..=MAX_POWER {
        let csv_file = format!("benches/csv/entry_2_{}.csv", i);

        let bench_name = format!("build merkle sum tree for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                MerkleSumTree::new(&csv_file).unwrap();
            })
        });
    }
}

fn verification_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in MIN_POWER..=MAX_POWER {
        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let empty_circuit = MerkleSumTreeCircuit::init_empty(i.try_into().unwrap());

        let bench_name = format!("gen verification key for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
            })
        });
    }
}

fn proving_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in MIN_POWER..=MAX_POWER {
        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let empty_circuit = MerkleSumTreeCircuit::init_empty(i.try_into().unwrap());

        let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
        let bench_name = format!("gen proving key for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                keygen_pk(&params, vk.clone(), &empty_circuit)
                    .expect("pk generation should not fail");
            })
        });
    }
}

fn generate_zk_proof_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in MIN_POWER..=MAX_POWER {
        let empty_circuit = MerkleSumTreeCircuit::init_empty(i.try_into().unwrap());

        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
        let pk =
            keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");

        let csv_file = format!("benches/csv/entry_2_{}.csv", i);

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MerkleSumTreeCircuit::init_from_assets_and_path(assets_sum, &csv_file, 0);

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

    for i in MIN_POWER..=MAX_POWER {
        let empty_circuit = MerkleSumTreeCircuit::init_empty(i.try_into().unwrap());

        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
        let pk =
            keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");

        let csv_file = format!("benches/csv/entry_2_{}.csv", i);

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MerkleSumTreeCircuit::init_from_assets_and_path(assets_sum, &csv_file, 0);

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

criterion_group!(
    benches,
    build_mstree_benchmark,
    verification_key_gen_benchmark,
    proving_key_gen_benchmark,
    generate_zk_proof_benchmark,
    verify_zk_proof_benchmark
);
criterion_main!(benches);
