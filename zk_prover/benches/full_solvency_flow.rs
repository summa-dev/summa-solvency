use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp},
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use summa_solvency::{
    circuits::merkle_sum_tree::MerkleSumTreeCircuit,
    circuits::utils::{full_prover, full_verifier, generate_setup_params},
    merkle_sum_tree::{MerkleSumTree, MST_WIDTH, N_ASSETS},
};

const LEVELS: usize = 5;
const SAMPLE_SIZE: usize = 10;

fn build_mstree_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let csv_file = format!("benches/csv/entry_2_{}.csv", LEVELS);

    let bench_name = format!("build merkle sum tree for 2 power of {} entries", LEVELS);
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            MerkleSumTree::<N_ASSETS>::new(&csv_file).unwrap();
        })
    });
}

fn verification_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MerkleSumTreeCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

    let bench_name = format!("gen verification key for 2 power of {} entries", LEVELS);
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
        })
    });
}

fn proving_key_gen_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MerkleSumTreeCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
    let bench_name = format!("gen proving key for 2 power of {} entries", LEVELS);
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");
        })
    });
}

fn generate_zk_proof_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MerkleSumTreeCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");

    let csv_file = format!("benches/csv/entry_2_{}.csv", LEVELS);

    let assets_sum = [Fp::from(556863u64), Fp::from(556863u64)]; // greater than liabilities sum (556862)

    // Only now we can instantiate the circuit with the actual inputs
    let circuit = MerkleSumTreeCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_from_assets_and_path(
        assets_sum, &csv_file, 0,
    );

    let mut public_input = vec![circuit.leaf_hash];
    public_input.extend(&circuit.leaf_balances);
    public_input.push(circuit.root_hash);
    public_input.extend(&circuit.assets_sum);

    let bench_name = format!("generate zk proof - tree of 2 power of {} entries", LEVELS);
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            full_prover(&params, &pk, circuit.clone(), &public_input);
        })
    });
}

fn verify_zk_proof_benchmark(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MerkleSumTreeCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");

    let csv_file = format!("benches/csv/entry_2_{}.csv", LEVELS);

    let assets_sum = [Fp::from(556863u64), Fp::from(556863u64)]; // greater than liabilities sum (556862)

    // Only now we can instantiate the circuit with the actual inputs
    let circuit = MerkleSumTreeCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_from_assets_and_path(
        assets_sum, &csv_file, 0,
    );

    let mut public_input = vec![circuit.leaf_hash];
    public_input.extend(&circuit.leaf_balances);
    public_input.push(circuit.root_hash);
    public_input.extend(&circuit.assets_sum);

    let proof = full_prover(&params, &pk, circuit, &public_input);

    let bench_name = format!("verify zk proof - tree of 2 power of {} entries", LEVELS);
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            full_verifier(&params, &vk, proof.clone(), &public_input);
        })
    });
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
