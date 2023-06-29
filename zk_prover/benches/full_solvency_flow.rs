use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::CircuitExt;
use summa_solvency::{
    circuits::merkle_sum_tree::MstInclusionCircuit,
    circuits::utils::{full_prover, full_verifier, generate_setup_params},
    merkle_sum_tree::MerkleSumTree,
};

const SAMPLE_SIZE: usize = 10;
const LEVELS: usize = 5;
const N_ASSETS: usize = 1;
const PATH_NAME: &str = "one_asset";
const L: usize = 2 + (N_ASSETS * 2);

fn build_mstree(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let csv_file = format!(
        "benches/csv/{}/{}_entry_2_{}.csv",
        PATH_NAME, PATH_NAME, LEVELS
    );

    let bench_name = format!(
        "build merkle sum tree for 2 power of {} entries with {} assets",
        LEVELS, N_ASSETS
    );

    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            MerkleSumTree::<N_ASSETS>::new(&csv_file).unwrap();
        })
    });
}

fn verification_key_gen_mst_inclusion_circuit(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();

    let bench_name = format!(
        "gen verification key for 2 power of {} entries with {} assets",
        LEVELS, N_ASSETS
    );
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
        })
    });
}

fn proving_key_gen_mst_inclusion_circuit(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();

    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
    let bench_name = format!(
        "gen proving key for 2 power of {} entries with {} assets",
        LEVELS, N_ASSETS
    );
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");
        })
    });
}

fn generate_zk_proof_mst_inclusion_circuit(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();

    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk, &empty_circuit).expect("pk generation should not fail");

    let csv_file = format!(
        "benches/csv/{}/{}_entry_2_{}.csv",
        PATH_NAME, PATH_NAME, LEVELS
    );

    // Only now we can instantiate the circuit with the actual inputs
    let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init(&csv_file, 0);

    let bench_name = format!(
        "generate zk proof - tree of 2 power of {} entries with {} assets",
        LEVELS, N_ASSETS
    );
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            full_prover(&params, &pk, circuit.clone(), circuit.instances());
        })
    });
}

fn verify_zk_proof_mst_inclusion_circuit(_c: &mut Criterion) {
    let mut criterion = Criterion::default().sample_size(SAMPLE_SIZE);

    let params: ParamsKZG<Bn256> = generate_setup_params(11);

    let empty_circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();

    let vk = keygen_vk(&params, &empty_circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &empty_circuit).expect("pk generation should not fail");

    let csv_file = format!(
        "benches/csv/{}/{}_entry_2_{}.csv",
        PATH_NAME, PATH_NAME, LEVELS
    );

    // Only now we can instantiate the circuit with the actual inputs
    let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init(&csv_file, 0);

    let proof = full_prover(&params, &pk, circuit.clone(), circuit.instances());

    println!("proof size in bytes: {}", proof.len());

    let bench_name = format!(
        "verify zk proof - tree of 2 power of {} entries with {} assets",
        LEVELS, N_ASSETS
    );
    criterion.bench_function(&bench_name, |b| {
        b.iter(|| {
            full_verifier(&params, &vk, proof.clone(), circuit.instances());
        })
    });
}

criterion_group!(
    benches,
    build_mstree,
    verification_key_gen_mst_inclusion_circuit,
    proving_key_gen_mst_inclusion_circuit,
    generate_zk_proof_mst_inclusion_circuit,
    verify_zk_proof_mst_inclusion_circuit
);
criterion_main!(benches);
