use halo2_proofs::arithmetic::Field;
use plonkish_backend::Error::InvalidSnark;
use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit},
    frontend::halo2::{CircuitExt, Halo2Circuit},
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::{multilinear::MultilinearKzg, Evaluation, PolynomialCommitmentScheme},
    util::{
        transcript::{
            FieldTranscriptRead, FieldTranscriptWrite, InMemoryTranscript, Keccak256Transcript,
        },
        Itertools,
    },
    Error::InvalidSumcheck,
};
use rand::{
    rngs::{OsRng, StdRng},
    CryptoRng, Rng, RngCore, SeedableRng,
};

use crate::{
    circuits::{
        config::{no_range_check_config::NoRangeCheckConfig, range_check_config::RangeCheckConfig},
        summa_circuit::SummaHyperplonk,
    },
    utils::{
        big_uint_to_fp, fp_to_big_uint, generate_dummy_entries, uni_to_multivar_binary_index,
        MultilinearAsUnivariate,
    },
};
const K: u32 = 17;
const N_CURRENCIES: usize = 3;
// One row is reserved for the grand total.
const N_USERS: usize = (1 << K) - 2;

pub fn seeded_std_rng() -> impl RngCore + CryptoRng {
    StdRng::seed_from_u64(OsRng.next_u64())
}

#[test]
fn test_summa_hyperplonk_e2e() {
    type ProvingBackend = HyperPlonk<MultilinearKzg<Bn256>>;
    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();

    let halo2_circuit =
        SummaHyperplonk::<N_USERS, N_CURRENCIES, RangeCheckConfig<N_CURRENCIES, N_USERS>>::init(
            entries.to_vec(),
        );

    let neg_grand_total = halo2_circuit.concatenated_grand_total.neg();

    // We're putting the negated grand total at the end of each balance column,
    // so the sumcheck over such balance column would yield zero (given the special gate,
    // see the circuit).
    assert!(neg_grand_total == halo2_circuit.instances()[0][1]);

    let num_vars = K;

    let circuit_fn = |num_vars| {
        let circuit = Halo2Circuit::<
            Fp,
            SummaHyperplonk<N_USERS, N_CURRENCIES, RangeCheckConfig<N_CURRENCIES, N_USERS>>,
        >::new::<ProvingBackend>(num_vars, halo2_circuit.clone());
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

    let invalid_grand_total_instances = instances[0]
        .iter()
        .enumerate()
        .map(|(i, element)| {
            if i == 0 {
                *element
            } else {
                Fp::random(seeded_std_rng())
            }
        })
        .collect::<Vec<_>>();

    let invalid_result = {
        let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
        ProvingBackend::verify(
            &verifier_parameters,
            &[invalid_grand_total_instances],
            &mut transcript,
            seeded_std_rng(),
        )
    };
    assert_eq!(
        invalid_result,
        Err(InvalidSumcheck(
            "Consistency failure at round 1".to_string()
        ))
    );

    let invalid_range_check_instances = instances[0]
        .iter()
        .enumerate()
        .map(|(i, element)| {
            if i == 0 {
                Fp::random(seeded_std_rng())
            } else {
                *element
            }
        })
        .collect::<Vec<_>>();

    let invalid_result = {
        let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());
        ProvingBackend::verify(
            &verifier_parameters,
            &[invalid_range_check_instances],
            &mut transcript,
            seeded_std_rng(),
        )
    };
    assert_eq!(
        invalid_result,
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
        entries[random_user_index].concatenated_balance().unwrap()
    );

    // Convert challenge into a multivariate form
    let multivariate_challenge: Vec<Fp> =
        uni_to_multivar_binary_index(&random_user_index, num_vars as usize);

    let mut kzg_transcript = Keccak256Transcript::new(());

    let mut transcript = Keccak256Transcript::from_proof((), proof.as_slice());

    // Username and Concatenated balance
    let num_points = 2;

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

    let evals = user_entry_polynomials
        .iter()
        .enumerate()
        .map(|(poly_idx, poly)| {
            Evaluation::new(poly_idx, 0, poly.evaluate(&multivariate_challenge))
        })
        .collect_vec();

    MultilinearKzg::<Bn256>::batch_open(
        &prover_parameters.pcs,
        user_entry_polynomials,
        &user_entry_commitments,
        &[multivariate_challenge],
        &evals,
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
    let mut multivariate_challenge: Vec<Fp> = Vec::new();
    for _ in 0..num_vars {
        multivariate_challenge.push(kzg_transcript.read_field_element().unwrap());
    }

    let evals = vec![
        Evaluation::new(
            0,
            0,
            big_uint_to_fp::<Fp>(entries[random_user_index].username_as_big_uint()),
        ),
        Evaluation::new(
            1,
            0,
            big_uint_to_fp::<Fp>(&entries[random_user_index].concatenated_balance().unwrap()),
        ),
    ];

    MultilinearKzg::<Bn256>::batch_verify(
        &verifier_parameters.pcs,
        &user_entry_commitments,
        &[multivariate_challenge],
        &evals,
        &mut kzg_transcript,
    )
    .unwrap();
}

/// Test the sumcheck failure case
/// The grand total is set to a random value, which will cause the sumcheck to fail
/// because the sum of all valid balances is not equal to the negated random grand total
#[test]
fn test_sumcheck_fail() {
    type ProvingBackend = HyperPlonk<MultilinearKzg<Bn256>>;
    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();

    let halo2_circuit = SummaHyperplonk::<
        N_USERS,
        N_CURRENCIES,
        NoRangeCheckConfig<N_CURRENCIES, N_USERS>,
    >::init_invalid_grand_total(entries.to_vec());

    let num_vars = K;

    let circuit_fn = |num_vars| {
        let circuit = Halo2Circuit::<
            Fp,
            SummaHyperplonk<N_USERS, N_CURRENCIES, NoRangeCheckConfig<N_CURRENCIES, N_USERS>>,
        >::new::<ProvingBackend>(num_vars, halo2_circuit.clone());
        (circuit.circuit_info().unwrap(), circuit)
    };

    let (circuit_info, circuit) = circuit_fn(num_vars as usize);
    let instances = circuit.instances();

    let param = ProvingBackend::setup(&circuit_info, seeded_std_rng()).unwrap();

    let (prover_parameters, verifier_parameters) =
        ProvingBackend::preprocess(&param, &circuit_info).unwrap();

    let (_, proof_transcript) = {
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
    assert_eq!(
        result,
        Err(InvalidSnark(
            "Unmatched between sum_check output and query evaluation".to_string()
        ))
    );
}

#[cfg(feature = "dev-graph")]
#[test]
fn print_univariate_grand_sum_circuit() {
    use plotters::prelude::*;

    let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();

    let circuit =
        SummaHyperplonk::<N_USERS, N_CURRENCIES, RangeCheckConfig<N_CURRENCIES, N_USERS>>::init(
            entries.to_vec(),
        );

    let root =
        BitMapBackend::new("prints/summa-hyperplonk-layout.png", (2048, 32768)).into_drawing_area();
    root.fill(&WHITE).unwrap();
    let root = root
        .titled("Summa Hyperplonk Layout", ("sans-serif", 60))
        .unwrap();

    halo2_proofs::dev::CircuitLayout::default()
        .render::<Fp, SummaHyperplonk<N_USERS, N_CURRENCIES,  RangeCheckConfig<N_CURRENCIES, N_USERS>>, _, true>(K, &circuit, &root)
        .unwrap();
}
