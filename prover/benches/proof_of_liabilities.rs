use criterion::{criterion_group, criterion_main, Criterion};
use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo},
    frontend::halo2::Halo2Circuit,
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::multilinear::MultilinearKzg,
    util::{
        test::std_rng,
        transcript::{InMemoryTranscript, Keccak256Transcript},
    },
};
use rand::{
    rngs::{OsRng, StdRng},
    CryptoRng, RngCore, SeedableRng,
};
use summa_hyperplonk::{
    circuits::summa_circuit::summa_hyperplonk::SummaHyperplonk, utils::generate_dummy_entries,
};

fn bench_summa<const K: u32, const N_USERS: usize, const N_CURRENCIES: usize>() {
    let name = format!("K = {K}, N_USERS = {N_USERS}, N_CURRENCIES = {N_CURRENCIES}");
    let mut c = Criterion::default().sample_size(10);

    let grand_sum_proof_bench_name = format!("<{}> grand sum proof", name);

    type Pb = HyperPlonk<MultilinearKzg<Bn256>>;
    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();
    let halo2_circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    let circuit = Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<Pb>(
        17,
        halo2_circuit.clone(),
    );

    let circuit_info: PlonkishCircuitInfo<_> = circuit.circuit_info().unwrap();
    let instances = circuit.instances();
    let param = Pb::setup(&circuit_info, seeded_std_rng()).unwrap();

    let (pp, vp) = Pb::preprocess(&param, &circuit_info).unwrap();

    let mut transcript = Keccak256Transcript::default();
    let proof = {
        Pb::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
        transcript.into_proof()
    };

    let accept = {
        let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
        Pb::verify(&vp, instances, &mut transcript, std_rng()).is_ok()
    };
    assert!(accept);

    c.bench_function(&grand_sum_proof_bench_name, |b| {
        b.iter_batched(
            || {
                Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<Pb>(
                    17,
                    halo2_circuit.clone(),
                )
            },
            |circuit| {
                let mut transcript = Keccak256Transcript::default();

                Pb::prove(&pp, &circuit, &mut transcript, std_rng()).unwrap();
                transcript.into_proof();
            },
            criterion::BatchSize::SmallInput, // Choose an appropriate batch size
        )
    });
}

fn criterion_benchmark(_c: &mut Criterion) {
    const N_CURRENCIES: usize = 2;

    {
        const K: u32 = 17;
        const N_USERS: usize = 1 << 16 as usize;
        bench_summa::<K, N_USERS, N_CURRENCIES>();
    }
}

pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
    StdRng::seed_from_u64(OsRng.next_u64())
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
