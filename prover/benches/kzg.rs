#![feature(generic_const_exprs)]
use criterion::{criterion_group, criterion_main, Criterion};
use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr as Fp};
use num_bigint::BigUint;
use rand::{rngs::OsRng, Rng};

#[cfg(feature = "no_range_check")]
use summa_solvency::circuits::univariate_grand_sum::NoRangeCheckConfig;
#[cfg(not(feature = "no_range_check"))]
use summa_solvency::circuits::univariate_grand_sum::UnivariateGrandSumConfig;
use summa_solvency::{
    circuits::{
        univariate_grand_sum::{CircuitConfig, UnivariateGrandSum},
        utils::{
            compute_h_parallel, full_prover, generate_setup_artifacts,
            open_all_user_points_amortized, open_grand_sums, open_grand_sums_gwc,
            open_single_user_point_amortized, open_user_points, verify_grand_sum_openings,
            verify_user_inclusion,
        },
    },
    utils::{big_uint_to_fp, generate_dummy_entries},
};

fn bench_kzg<
    const K: u32,
    const N_USERS: usize,
    const N_CURRENCIES: usize,
    CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
>(
    name: &str,
) where
    [(); N_CURRENCIES + 1]:,
{
    let mut c = Criterion::default().sample_size(10);

    // Initialize an empty circuit
    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES, CONFIG>::init_empty();
    let (params, pk, vk) = generate_setup_artifacts(K, None, &circuit).unwrap();

    let range_check_proof_bench_name = format!("<{}> range check", name);
    let opening_grand_sum_bench_name = format!("<{}> opening grand sum", name);
    let opening_user_bench_name = format!("<{}> opening single user inclusion", name);
    let calculate_h_bench_name =
        format!("<{}> calculating h(X) for the amortized KZG approach", name);
    let amortized_opening_all_bench_name = format!(
        "<{}> opening all 2^{} user inclusions using the amortized approach",
        name, K
    );
    let amortized_opening_user_bench_name = format!(
        "<{}> opening single user inclusion using the amortized approach",
        name
    );
    let verifying_grand_sum_bench_name = format!("<{}> verifying grand sum", name);
    let verifying_user_bench_name = format!("<{}> verifying user inclusion", name);

    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();

    // Calculate total for all entry columns
    let mut total_balances: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

    for entry in &entries {
        for (i, balance) in entry.balances().iter().enumerate() {
            total_balances[i] += balance;
        }
    }

    let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES, CONFIG>::init(entries.to_vec());

    c.bench_function(&range_check_proof_bench_name, |b| {
        b.iter_batched(
            || circuit.clone(), // Setup function: clone the circuit for each iteration
            |circuit| {
                full_prover(&params, &pk, circuit, &[vec![Fp::zero()]]);
            },
            criterion::BatchSize::SmallInput, // Choose an appropriate batch size
        );
    });

    let (zk_snark_proof, advice_polys, omega) =
        full_prover(&params, &pk, circuit, &[vec![Fp::zero()]]);

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
                    total_balances
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
                    total_balances
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

    c.bench_function(&calculate_h_bench_name, |b| {
        b.iter_batched(
            || (0..N_CURRENCIES + 1),
            |column_range| compute_h_parallel(&advice_polys.advice_polys, &params, column_range),
            criterion::BatchSize::SmallInput,
        );
    });

    let h_vectors = compute_h_parallel(&advice_polys.advice_polys, &params, 0..N_CURRENCIES + 1);
    let vec_of_slices = h_vectors.iter().map(|v| v.as_slice()).collect::<Vec<_>>();
    let h_slices = vec_of_slices.as_slice();

    c.bench_function(&amortized_opening_all_bench_name, |b| {
        b.iter_batched(
            || {},
            |_| open_all_user_points_amortized(h_slices, omega),
            criterion::BatchSize::SmallInput,
        );
    });

    c.bench_function(&amortized_opening_user_bench_name, |b| {
        b.iter_batched(
            || {},
            |_| open_single_user_point_amortized(h_slices, &params, omega),
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
        total_balances
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
                verify_user_inclusion(
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
    const N_CURRENCIES: usize = 1;

    // Demonstrating that a higher value of K has a more significant impact on benchmark performance than the number of users
    #[cfg(not(feature = "no_range_check"))]
    {
        const K: u32 = 17;
        const N_USERS: usize = 2usize.pow(K) - 6;
        bench_kzg::<K, N_USERS, N_CURRENCIES, UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
        );
    }
    //Use the following benchmarks for quick evaluation/prototyping (no range check)
    #[cfg(feature = "no_range_check")]
    {
        const K: u32 = 9;
        const N_USERS: usize = 2usize.pow(K) - 6;
        bench_kzg::<K, N_USERS, N_CURRENCIES, NoRangeCheckConfig<N_CURRENCIES, N_USERS>>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
        );
    }
    #[cfg(feature = "no_range_check")]
    {
        const K: u32 = 10;
        const N_USERS: usize = 2usize.pow(K) - 6;
        bench_kzg::<K, N_USERS, N_CURRENCIES, NoRangeCheckConfig<N_CURRENCIES, N_USERS>>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
        );
    }
    #[cfg(feature = "no_range_check")]
    {
        const K: u32 = 11;
        const N_USERS: usize = 2usize.pow(K) - 6;
        bench_kzg::<K, N_USERS, N_CURRENCIES, NoRangeCheckConfig<N_CURRENCIES, N_USERS>>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
        );
    }
    #[cfg(feature = "no_range_check")]
    {
        const K: u32 = 12;
        const N_USERS: usize = 2usize.pow(K) - 6;
        bench_kzg::<K, N_USERS, N_CURRENCIES, NoRangeCheckConfig<N_CURRENCIES, N_USERS>>(
            format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}").as_str(),
        );
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
