use halo2_proofs::arithmetic::Field;
use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit},
    frontend::halo2::Halo2Circuit,
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::{multilinear::MultilinearKzg, PolynomialCommitmentScheme},
    util::transcript::{
        FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript, Keccak256Transcript,
    },
    Error::InvalidSumcheck,
};

use rand::{
    rngs::{OsRng, StdRng},
    CryptoRng, Rng, RngCore, SeedableRng,
};

use crate::{
    circuits::summa_circuit::summa_hyperplonk::SummaHyperplonk,
    utils::{
        big_uint_to_fp, fp_to_big_uint, generate_dummy_entries, uni_to_multivar_binary_index,
        MultilinearAsUnivariate,
    },
};
const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 1 << 16;

pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
    StdRng::seed_from_u64(OsRng.next_u64())
}

#[test]
fn test_summa_hyperplonk() {
    type ProvingBackend = HyperPlonk<MultilinearKzg<Bn256>>;
    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();
    let circuit = SummaHyperplonk::<N_USERS, N_CURRENCIES>::init(entries.to_vec());
    let num_vars = K;

    let circuit_fn = |num_vars| {
        let circuit = Halo2Circuit::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES>>::new::<
            ProvingBackend,
        >(num_vars, circuit.clone());
        (circuit.circuit_info().unwrap(), circuit)
    };

    let (circuit_info, circuit) = circuit_fn(num_vars as usize);
    let instances = circuit.instances();

    let param = ProvingBackend::setup(&circuit_info, seeded_std_rng()).unwrap();

    let (prover_parameters, verifier_parameters) =
        ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let (witness_polys, proof_transcript) = {
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

    let num_points = 3;

    let proof = proof_transcript.into_proof();

    let mut transcript;
    let result: Result<(), plonkish_backend::Error> = {
        transcript = Keccak256Transcript::from_proof((), proof.as_slice());
        ProvingBackend::verify(
            &verifier_parameters,
            instances,
            &mut transcript,
            seeded_std_rng(),
        )
    };
    assert_eq!(result, Ok(()));

    let wrong_instances = instances[0]
        .iter()
        .map(|instance| *instance + Fp::ONE)
        .collect::<Vec<_>>();
    let wrong_result = {
        let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
        ProvingBackend::verify(
            &verifier_parameters,
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

    //Create an evaluation challenge at a random "user index"
    let fraction: f64 = rand::thread_rng().gen();
    let random_user_index = (fraction * (entries.len() as f64)) as usize;

    assert_eq!(
        fp_to_big_uint(&witness_polys[0].evaluate_as_univariate(&random_user_index)),
        *entries[random_user_index].username_as_big_uint()
    );
    assert_eq!(
        fp_to_big_uint(&witness_polys[1].evaluate_as_univariate(&random_user_index)),
        entries[random_user_index].balances()[0]
    );

    // Convert challenge into a multivariate form
    let multivariate_challenge =
        uni_to_multivar_binary_index(&random_user_index, num_vars as usize);

    let mut kzg_transcript = Keccak256Transcript::new(());

    let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());

    let user_entry_commitments = MultilinearKzg::<Bn256>::read_commitments(
        &verifier_parameters.pcs,
        num_points,
        &mut transcript,
    )
    .unwrap();
    let user_entry_polynomials = witness_polys.iter().take(num_points).collect::<Vec<_>>();

    //Store the user index multi-variable in the transcript for the verifier
    for binary_var in multivariate_challenge.iter() {
        kzg_transcript.write_field_element(binary_var).unwrap();
    }

    MultilinearKzg::<Bn256>::open(
        &prover_parameters.pcs,
        user_entry_polynomials[0],
        &user_entry_commitments[0],
        &multivariate_challenge,
        &user_entry_polynomials[0].evaluate(&multivariate_challenge),
        &mut kzg_transcript,
    )
    .unwrap();

    let kzg_proof = kzg_transcript.into_proof();

    // Verifier side
    let mut kzg_transcript = Keccak256Transcript::from_proof((), kzg_proof.as_slice());

    // The verifier knows the ZK-SNARK proof, can extract the polynomial commitments
    let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
    let user_entry_commitments = MultilinearKzg::<Bn256>::read_commitments(
        &verifier_parameters.pcs,
        num_points,
        &mut transcript,
    )
    .unwrap();

    //The verifier doesn't know the mapping of their "user index" to the multi-variable index, reads it from the transcript
    let mut multivariate_challenge = Vec::new();
    for _ in 0..num_vars {
        multivariate_challenge.push(kzg_transcript.read_field_element().unwrap());
    }

    MultilinearKzg::<Bn256>::verify(
        &verifier_parameters.pcs,
        &user_entry_commitments[0],
        &multivariate_challenge,
        //The user knows their evaluation at the challenge point
        &big_uint_to_fp(entries[random_user_index].username_as_big_uint()),
        &mut kzg_transcript,
    )
    .unwrap();
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
