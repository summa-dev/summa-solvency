use criterion::{criterion_group, criterion_main, Criterion};
use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo},
    frontend::halo2::Halo2Circuit,
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::{multilinear::MultilinearKzg, Evaluation, PolynomialCommitmentScheme},
    util::{
        test::std_rng,
        transcript::{InMemoryTranscript, Keccak256Transcript},
    },
};
use rand::{
    rngs::{OsRng, StdRng},
    CryptoRng, Rng, RngCore, SeedableRng,
};
use summa_hyperplonk::{
    circuits::summa_circuit::summa_hyperplonk::SummaHyperplonk,
    utils::{big_uint_to_fp, generate_dummy_entries, uni_to_multivar_binary_index},
};

fn bench_summa<const K: u32, const N_USERS: usize, const N_CURRENCIES: usize>() {
    let name = format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}");
    let mut c = Criterion::default().sample_size(10);

    let grand_sum_proof_bench_name = format!("<{}> grand sum proof", name);
    let inclusion_proof_bench_name = format!("<{}> user inclusion proof", name);

    let grand_sum_verification_bench_name = format!("<{}> grand sum verification", name);
    let inclusion_verification_bench_name = format!("<{}> user inclusion verification", name);

    type ProvingBackend = HyperPlonk<MultilinearKzg<Bn256>>;
    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();
    let halo2_circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    let circuit = Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<ProvingBackend>(
        K as usize,
        halo2_circuit.clone(),
    );

    let circuit_info: PlonkishCircuitInfo<_> = circuit.circuit_info().unwrap();
    let instances = circuit.instances();
    let param = ProvingBackend::setup(&circuit_info, seeded_std_rng()).unwrap();

    let (pp, vp) = ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let mut transcript = Keccak256Transcript::default();
    let proof = {
        ProvingBackend::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        transcript.into_proof()
    };

    c.bench_function(&grand_sum_proof_bench_name, |b| {
        b.iter_batched(
            || {
                Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<ProvingBackend>(
                    K as usize,
                    halo2_circuit.clone(),
                )
            },
            |circuit| {
                let mut transcript = Keccak256Transcript::default();

                ProvingBackend::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
                transcript.into_proof();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    let (prover_parameters, verifier_parameters) =
        ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let (witness_polys, _) = {
        let mut proof_transcript = Keccak256Transcript::new(());

        let witness_polys = ProvingBackend::prove(
            &prover_parameters,
            &circuit,
            &mut proof_transcript,
            seeded_std_rng(),
        )
        .unwrap();
        (witness_polys, proof_transcript)
    };
    let num_points = N_CURRENCIES + 1;
    let user_entry_polynomials = witness_polys.iter().take(num_points).collect::<Vec<_>>();
    let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());

    let user_entry_commitments = MultilinearKzg::<Bn256>::read_commitments(
        &verifier_parameters.pcs,
        num_points,
        &mut transcript,
    )
    .unwrap();

    //Create an evaluation challenge at a random "user index"
    let fraction: f64 = rand::thread_rng().gen();
    let random_user_index = (fraction * (entries.len() as f64)) as usize;

    let num_vars = K;

    let multivariate_challenge =
        uni_to_multivar_binary_index(&random_user_index, num_vars as usize);

    let mut evals = vec![];

    for i in 0..N_CURRENCIES + 1 {
        if i == 0 {
            evals.push(Evaluation::new(
                i,
                0,
                big_uint_to_fp::<Fp>(entries[random_user_index].username_as_big_uint()),
            ));
        } else {
            evals.push(Evaluation::new(
                i,
                0,
                big_uint_to_fp::<Fp>(&entries[random_user_index].balances()[i - 1]),
            ));
        }
    }

    c.bench_function(&inclusion_proof_bench_name, |b| {
        b.iter_batched(
            || {
                (
                    user_entry_polynomials.clone(),
                    multivariate_challenge.clone(),
                )
            },
            |(user_entry_polynomials, multivariate_challenge)| {
                let mut kzg_transcript = Keccak256Transcript::new(());
                MultilinearKzg::<Bn256>::batch_open(
                    &prover_parameters.pcs,
                    user_entry_polynomials,
                    &user_entry_commitments,
                    &[multivariate_challenge],
                    &evals,
                    &mut kzg_transcript,
                )
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function(&grand_sum_verification_bench_name, |b| {
        b.iter_batched(
            || (Keccak256Transcript::from_proof((), proof.as_slice())),
            |mut transcript| {
                let accept =
                    { ProvingBackend::verify(&vp, instances, &mut transcript, std_rng()).is_ok() };
                assert!(accept);
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function(&inclusion_verification_bench_name, |b| {
        b.iter_batched(
            || {
                let mut kzg_transcript = Keccak256Transcript::new(());
                MultilinearKzg::<Bn256>::batch_open(
                    &prover_parameters.pcs,
                    user_entry_polynomials.clone(),
                    &user_entry_commitments,
                    &[multivariate_challenge.clone()],
                    &evals,
                    &mut kzg_transcript,
                )
                .unwrap();
                (kzg_transcript.into_proof(), multivariate_challenge.clone())
            },
            |(kzg_proof, multivariate_challenge)| {
                let mut kzg_transcript = Keccak256Transcript::from_proof((), kzg_proof.as_slice());
                MultilinearKzg::<Bn256>::batch_verify(
                    &verifier_parameters.pcs,
                    &user_entry_commitments,
                    &[multivariate_challenge],
                    &evals,
                    &mut kzg_transcript,
                )
                .unwrap();
            },
            criterion::BatchSize::SmallInput,
        )
    });
}

fn criterion_benchmark(_c: &mut Criterion) {
    const N_CURRENCIES: usize = 1;

    {
        const K: u32 = 17;
        const N_USERS: usize = (1 << K as usize) - 6;
        bench_summa::<K, N_USERS, N_CURRENCIES>();
    }
}

pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
    StdRng::seed_from_u64(OsRng.next_u64())
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
