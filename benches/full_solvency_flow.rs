use circuits_halo2::merkle_sum_tree::{MerkleSumTree};
use criterion::{criterion_group, criterion_main, Criterion};

const MAX_POWER: u32 = 6;
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

criterion_group!(benches, build_tree_benchmark);
criterion_main!(benches);
