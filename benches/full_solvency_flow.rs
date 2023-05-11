use circuits_halo2::{
    circuits::utils::{
        full_prover, full_verifier, generate_setup_params, instantiate_circuit,
        instantiate_empty_circuit,
    },
    merkle_sum_tree::MerkleSumTree,
};
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp},
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use std::convert::TryInto;

const MIN_POWER: u32 = 4;
const MAX_POWER: u32 = 27;
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

        let bench_name = format!("gen verification key for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                keygen_vk(&params, &instantiate_empty_circuit(i.try_into().unwrap()))
                    .expect("vk generation should not fail");
            })
        });
    }
}

fn proving_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in MIN_POWER..=MAX_POWER {
        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let vk = keygen_vk(&params, &instantiate_empty_circuit(i.try_into().unwrap()))
            .expect("vk generation should not fail");
        let bench_name = format!("gen proving key for 2 power of {} entries", i);
        criterion.bench_function(&bench_name, |b| {
            b.iter(|| {
                keygen_pk(
                    &params,
                    vk.clone(),
                    &instantiate_empty_circuit(i.try_into().unwrap()),
                )
                .expect("pk generation should not fail");
            })
        });
    }
}

fn generate_zk_proof_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    for i in MIN_POWER..=MAX_POWER {
        let circuit = instantiate_empty_circuit(i.try_into().unwrap());

        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let csv_file = format!("benches/csv/entry_2_{}.csv", i);

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

    for i in MIN_POWER..=MAX_POWER {
        let circuit = instantiate_empty_circuit(i.try_into().unwrap());

        let params: ParamsKZG<Bn256> = generate_setup_params(i.try_into().unwrap());

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let csv_file = format!("benches/csv/entry_2_{}.csv", i);

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

criterion_group!(
    benches,
    build_mstree_benchmark,
    verification_key_gen_benchmark,
    proving_key_gen_benchmark,
    generate_zk_proof_benchmark,
    verify_zk_proof_benchmark
);
criterion_main!(benches);
