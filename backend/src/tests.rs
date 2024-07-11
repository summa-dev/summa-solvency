#[cfg(test)]
mod test {
    use rand::{rngs::OsRng, Rng};

    use plonkish_backend::{
        backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit},
        frontend::halo2::Halo2Circuit,
        halo2_curves::bn256::{Bn256, Fr as Fp},
        pcs::{multilinear::MultilinearKzg, Evaluation, PolynomialCommitmentScheme},
        util::{
            test::seeded_std_rng,
            transcript::{FieldTranscriptRead, InMemoryTranscript, Keccak256Transcript},
        },
    };

    use crate::apis::round::Round;
    use summa_hyperplonk::{
        circuits::summa_circuit::summa_hyperplonk::SummaHyperplonk,
        utils::{big_uint_to_fp, generate_dummy_entries},
    };

    const K: u32 = 17;
    const N_CURRENCIES: usize = 2;
    const N_USERS: usize = 16;
    const PARAMS_PATH: &str = "../backend/ptau/hermez-raw-plonkish-17";

    #[test]
    fn test_round_features() {
        type ProvingBackend = HyperPlonk<MultilinearKzg<Bn256>>;

        // Initialize Round.
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

        // Create a SNARK proof
        let param = ProvingBackend::setup_custom(PARAMS_PATH).unwrap();

        let (prover_params, verifier_params) =
            ProvingBackend::preprocess(&param, &circuit_info).unwrap();

        let (advice_polys, proof_transcript) = {
            let mut proof_transcript = Keccak256Transcript::new(());

            let advice_polys = ProvingBackend::prove(
                &prover_params,
                &circuit,
                &mut proof_transcript,
                seeded_std_rng(),
            )
            .unwrap();
            (advice_polys, proof_transcript)
        };

        let zk_snark_proof = proof_transcript.into_proof();

        let mut transcript;
        let result: Result<(), plonkish_backend::Error> = {
            transcript = Keccak256Transcript::from_proof((), zk_snark_proof.as_slice());
            ProvingBackend::verify(
                &verifier_params,
                instances,
                &mut transcript,
                seeded_std_rng(),
            )
        };
        assert_eq!(result, Ok(()));

        let snapshot_time = 1u64;
        let mut round = Round::<N_CURRENCIES, N_USERS>::new(
            zk_snark_proof.clone(),
            advice_polys,
            prover_params,
            verifier_params.clone(),
            snapshot_time,
        );

        let (commitment_proof, vp) = round.gen_commitment_and_vp().unwrap();
        // Checks return proof and verifier params are the same
        assert_eq!(commitment_proof.get_proof(), &zk_snark_proof);
        for i in 0..num_vars as usize {
            assert_eq!(vp.pcs.ss(i), verifier_params.pcs.ss(i));
        }

        // Generate and verify an inclusion proof for a random user.
        let user_range: std::ops::Range<usize> = 0..N_USERS;
        let random_user_index = OsRng.gen_range(user_range) as usize;
        let inclusion_proof = round.get_proof_of_inclusion(random_user_index).unwrap();

        // Check inclusion proof is not none
        assert!(inclusion_proof.get_proof().len() > 0);
        assert_eq!(inclusion_proof.get_input_values().len(), N_CURRENCIES + 1);

        // Verifier side
        let mut kzg_transcript =
            Keccak256Transcript::from_proof((), inclusion_proof.get_proof().as_slice());

        // The verifier knows the ZK-SNARK proof, can extract the polynomial commitments
        let mut transcript = Keccak256Transcript::from_proof((), zk_snark_proof.as_slice());
        let user_entry_commitments = MultilinearKzg::<Bn256>::read_commitments(
            &verifier_params.pcs,
            N_CURRENCIES + 1,
            &mut transcript,
        )
        .unwrap();

        let mut multivariate_challenge: Vec<Fp> = Vec::new();
        for _ in 0..num_vars {
            multivariate_challenge.push(kzg_transcript.read_field_element().unwrap());
        }

        // Assumed that the user already knows their evaluation, which is balances, at the challenge point
        let evals: Vec<Evaluation<Fp>> = (0..N_CURRENCIES + 1)
            .map(|i| {
                if i == 0 {
                    Evaluation::new(
                        i,
                        0,
                        big_uint_to_fp::<Fp>(entries[random_user_index].username_as_big_uint()),
                    )
                } else {
                    Evaluation::new(
                        i,
                        0,
                        big_uint_to_fp::<Fp>(&entries[random_user_index].balances()[i - 1]),
                    )
                }
            })
            .collect();

        MultilinearKzg::<Bn256>::batch_verify(
            &verifier_params.pcs,
            &user_entry_commitments,
            &[multivariate_challenge.clone()],
            &evals,
            &mut kzg_transcript,
        )
        .unwrap();
    }
}
