use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo},
    frontend::halo2::Halo2Circuit,
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::{multilinear::MultilinearKzg, PolynomialCommitmentScheme},
    util::{
        arithmetic::PrimeField,
        transcript::{InMemoryTranscript, Keccak256Transcript, TranscriptRead, TranscriptWrite},
        DeserializeOwned, Serialize,
    },
    Error::InvalidSumcheck,
};
use std::hash::Hash;

use rand::{
    rngs::{OsRng, StdRng},
    CryptoRng, RngCore, SeedableRng,
};

use crate::{
    circuits::summa_circuit::summa_hyperplonk::SummaHyperplonk, utils::generate_dummy_entries,
};
const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 1 << 16;

pub fn run_plonkish_backend<F, Pb, T, C>(
    num_vars: usize,
    circuit_fn: impl Fn(usize) -> (PlonkishCircuitInfo<F>, C),
) where
    F: PrimeField + Hash + Serialize + DeserializeOwned,
    Pb: PlonkishBackend<F>,
    T: TranscriptRead<<Pb::Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>
        + TranscriptWrite<<Pb::Pcs as PolynomialCommitmentScheme<F>>::CommitmentChunk, F>
        + InMemoryTranscript<Param = ()>,
    C: PlonkishCircuit<F>,
{
    let (circuit_info, circuit) = circuit_fn(num_vars);
    let instances = circuit.instances();

    let param = Pb::setup(&circuit_info, seeded_std_rng()).unwrap();

    let (pp, vp) = Pb::preprocess(&param, &circuit_info).unwrap();

    let proof = {
        let mut transcript = T::new(());
        Pb::prove(&pp, &circuit, &mut transcript, seeded_std_rng()).unwrap();
        transcript.into_proof()
    };

    let result = {
        let mut transcript = T::from_proof((), proof.as_slice());
        Pb::verify(&vp, instances, &mut transcript, seeded_std_rng())
    };
    assert_eq!(result, Ok(()));

    let wrong_instances = instances[0]
        .iter()
        .map(|instance| *instance + F::ONE)
        .collect::<Vec<_>>();
    let wrong_result = {
        let mut transcript = T::from_proof((), proof.as_slice());
        Pb::verify(
            &vp,
            &vec![wrong_instances],
            &mut transcript,
            seeded_std_rng(),
        )
    };
    assert_eq!(
        wrong_result,
        Err(InvalidSumcheck(
            "Consistency failure at round 1".to_string()
        ))
    );
}

pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
    StdRng::seed_from_u64(OsRng.next_u64())
}

#[test]
fn test_summa_hyperplonk() {
    type Pb = HyperPlonk<MultilinearKzg<Bn256>>;
    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();
    let circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init(entries.to_vec());
    let num_vars = K;
    run_plonkish_backend::<Fp, Pb, Keccak256Transcript<_>, _>(
        num_vars.try_into().unwrap(),
        |num_vars| {
            let circuit = Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<Pb>(
                num_vars,
                circuit.clone(),
            );
            (circuit.circuit_info().unwrap(), circuit)
        },
    );
}

#[cfg(feature = "dev-graph")]
#[test]
fn print_univariate_grand_sum_circuit() {
    use plotters::prelude::*;

    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();

    let circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    let root =
        BitMapBackend::new("prints/summa-hyperplonk-layout.png", (2048, 32768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Summa Hyperplonk Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .render::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>, _, true>(K, &circuit, &root)
        .unwrap();
}
