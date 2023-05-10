use circuits_halo2::{
    merkle_sum_tree::{MerkleSumTree},
    circuits::utils::{instantiate_empty_circuit},
};
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{
    halo2curves::bn256::Bn256,
    plonk::{keygen_pk, keygen_vk},
    poly::kzg::commitment::ParamsKZG,
};
use rand::rngs::OsRng;


const MAX_POWER: u32 = 10;
const SAMPLE_SIZE: usize = 10;

fn build_tree_benchmark(_c: &mut Criterion) {
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

criterion_group!(benches, build_tree_benchmark, verification_key_gen_benchmark, proving_key_gen_benchmark);
criterion_main!(benches);