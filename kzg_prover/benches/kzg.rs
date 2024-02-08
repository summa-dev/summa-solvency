#![feature(generic_const_exprs)]
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr as Fp};
use num_bigint::BigUint;
use rand::{rngs::OsRng, Rng};

use summa_solvency::{
    circuits::{
        univariate_grand_sum::UnivariateGrandSum,
        utils::{
            full_prover, generate_setup_artifacts, open_grand_sums, open_grand_sums_gwc,
            open_user_points, open_user_points_amortized, verify_grand_sum_openings,
            verify_user_inclusion,
        },
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::{big_uint_to_fp, parse_csv_to_entries},
};

fn bench_kzg<const K: u32, const N_USERS: usize, const N_CURRENCIES: usize, const N_POINTS: usize>(
    name: &str,
    csv_path: &str,
) where
    [(); N_CURRENCIES + 1]:,
{
    let mut c = Criterion::default().sample_size(10);

    // Initialize an empty circuit
    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();
    let (params, pk, vk) = generate_setup_artifacts(K, None, &circuit).unwrap();

    let range_check_bench_name = format!("<{}> range check", name);
    let opening_grand_sum_bench_name = format!("<{}> opening grand sum", name);
    let opening_user_bench_name = format!("<{}> opening user inclusion", name);
    let amortized_opening_user_bench_name =
        format!("<{}> amortized opening all 2^{} user inclusions", name, K);
    let verifying_grand_sum_bench_name = format!("<{}> verifying grand sum", name);
    let verifying_user_bench_name = format!("<{}> verifying user inclusion", name);

    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
    parse_csv_to_entries::<&str, N_CURRENCIES>(csv_path, &mut entries, &mut cryptos).unwrap();

    // Calculate total for all entry columns
    let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

    for entry in &entries {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total[i] += balance;
        }
    }

    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    c.bench_function(&range_check_bench_name, |b| {
        b.iter_batched(
            || circuit.clone(), // Setup function: clone the circuit for each iteration
            |circuit| {
                full_prover(&params, &pk, circuit, &[vec![]]);
            },
            criterion::BatchSize::SmallInput, // Choose an appropriate batch size
        );
    });

    let (zk_snark_proof, advice_polys, omega) = full_prover(&params, &pk, circuit, &[vec![]]);

    let poly_length = 1 << u64::from(K);

    c.bench_function(&opening_grand_sum_bench_name, |b| {
        b.iter_batched(
            || 1..N_CURRENCIES + 1,
            |balance_column_range| {
                open_grand_sums(
                    &advice_polys.advice_polys,
                    &advice_polys.advice_blinds,
                    &params,
                    balance_column_range,
                    csv_total
                        .iter()
                        .map(|x| big_uint_to_fp(&(x)) * Fp::from(poly_length).invert().unwrap())
                        .collect::<Vec<Fp>>()
                        .as_slice(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function(&format!("{} gwc", opening_grand_sum_bench_name), |b| {
        b.iter_batched(
            || 1..N_CURRENCIES + 1,
            |balance_column_range| {
                open_grand_sums_gwc(
                    &advice_polys.advice_polys,
                    &advice_polys.advice_blinds,
                    &params,
                    balance_column_range,
                    csv_total
                        .iter()
                        .map(|x| big_uint_to_fp(&(x)) * Fp::from(poly_length).invert().unwrap())
                        .collect::<Vec<Fp>>()
                        .as_slice(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Generate a random user index
    let get_random_user_index = || {
        let user_range: std::ops::Range<usize> = 0..N_USERS;
        OsRng.gen_range(user_range) as u16
    };

    c.bench_function(&opening_user_bench_name, |b| {
        b.iter_batched(
            || (get_random_user_index(), 0..N_CURRENCIES + 1),
            |(user_index, column_range)| {
                open_user_points(
                    &advice_polys.advice_polys,
                    &advice_polys.advice_blinds,
                    &params,
                    column_range,
                    omega,
                    user_index,
                    &entries
                        .get(user_index as usize)
                        .map(|entry| {
                            std::iter::once(big_uint_to_fp(&(entry.username_as_big_uint())))
                                .chain(entry.balances().iter().map(|x| big_uint_to_fp(x)))
                                .collect::<Vec<Fp>>()
                        })
                        .unwrap(),
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function(&amortized_opening_user_bench_name, |b| {
        b.iter_batched(
            || (0..N_CURRENCIES + 1),
            |column_range| {
                open_user_points_amortized(&advice_polys.advice_polys, &params, column_range, omega)
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Open grand sum for benchmark verifying grand sum
    let balance_column_range = 1..N_CURRENCIES + 1;
    let grand_sums_batch_proof = open_grand_sums(
        &advice_polys.advice_polys,
        &advice_polys.advice_blinds,
        &params,
        balance_column_range.clone(),
        csv_total
            .iter()
            .map(|x| big_uint_to_fp(&(x)) * Fp::from(poly_length).invert().unwrap())
            .collect::<Vec<Fp>>()
            .as_slice(),
    );

    c.bench_function(&verifying_grand_sum_bench_name, |b| {
        b.iter_batched(
            || {
                (
                    grand_sums_batch_proof.clone(),
                    u64::try_from(advice_polys.advice_polys[0].len()).unwrap(),
                    balance_column_range.clone(),
                )
            },
            |(grand_sums_batch_proof, poly_length, balance_column_range)| {
                verify_grand_sum_openings::<N_CURRENCIES>(
                    &params,
                    &zk_snark_proof,
                    &grand_sums_batch_proof,
                    poly_length,
                    balance_column_range,
                )
            },
            criterion::BatchSize::SmallInput,
        );
    });

    // Open user inclusion for benchmark verifying user inclusion
    let column_range = 0..N_CURRENCIES + 1;
    let omega = vk.get_domain().get_omega();
    let user_index = get_random_user_index();
    let openings_batch_proof = open_user_points(
        &advice_polys.advice_polys,
        &advice_polys.advice_blinds,
        &params,
        column_range.clone(),
        omega,
        user_index,
        &entries
            .get(user_index as usize)
            .map(|entry| {
                std::iter::once(big_uint_to_fp(&(entry.username_as_big_uint())))
                    .chain(entry.balances().iter().map(|x| big_uint_to_fp(x)))
                    .collect::<Vec<Fp>>()
            })
            .unwrap(),
    );

    c.bench_function(&verifying_user_bench_name, |b| {
        b.iter_batched(
            || (column_range.clone(), omega, user_index),
            |(column_range, omega, user_index)| {
                verify_user_inclusion::<N_POINTS>(
                    &params,
                    &zk_snark_proof,
                    &openings_batch_proof,
                    column_range,
                    omega,
                    user_index,
                );
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

fn criterion_benchmark(_c: &mut Criterion) {
    const N_CURRENCIES: usize = 2;
    const N_POINTS: usize = 3;

    // Demonstrating that a higher value of K has a more significant impact on benchmark performance than the number of users
    {
        const K: u32 = 18;
        const N_USERS: usize = 16;
        bench_kzg::<K, N_USERS, N_CURRENCIES, N_POINTS>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
            format!("../csv/entry_{N_USERS}.csv").as_str(),
        );
    }
    {
        const K: u32 = 17;
        const N_USERS: usize = 64;
        bench_kzg::<K, N_USERS, N_CURRENCIES, N_POINTS>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
            format!("../csv/entry_{N_USERS}.csv").as_str(),
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
