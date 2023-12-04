#[cfg(test)]
mod test {

    use crate::circuits::solvency_v2::SolvencyV2;
    use crate::circuits::utils::{full_prover, full_verifier, generate_setup_artifacts};
    use crate::utils::parse_csv_to_entries;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };
    use num_bigint::{BigUint, ToBigUint};
    //use snark_verifier_sdk::CircuitExt;

    const K: u32 = 9;

    const N_BYTES_V2: usize = 8;
    const N_ASSETS_V2: usize = 2;
    const N_USERS_V2: usize = 16;

    #[test]
    fn test_valid_solvency_v2() {
        let path = "src/csv/entry_16.csv";

        let (_, entries) = parse_csv_to_entries::<&str, N_ASSETS_V2, N_BYTES_V2>(path).unwrap();

        let circuit = SolvencyV2::<N_BYTES_V2, N_USERS_V2, N_ASSETS_V2>::init(entries);

        let valid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        assert_eq!(valid_prover.verify_par(), Ok(()))
    }

    // #[test]
    // fn test_overflow_solvency_v2() {
    //     let path = "src/merkle_sum_tree/csv/entry_16_overflow.csv";

    //     // Setting N_BYTES to 9 to not trigger the overflow error during the parsing of the csv
    //     let (_, entries) =
    //         parse_csv_to_entries::<&str, N_ASSETS_V2, { N_BYTES_V2 + 1 }>(path).unwrap();

    //     let circuit = SolvencyV2::<N_BYTES_V2, N_USERS_V2, N_ASSETS_V2>::init(entries);

    //     let invalid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

    //     assert_eq!(
    //         invalid_prover.verify(),
    //         Err(vec![VerifyFailure::Lookup {
    //             name: "advice cell should be in range [0, 2^8 - 1]".to_string(),
    //             lookup_index: (0),
    //             location: FailureLocation::InRegion {
    //                 region: (0, "assign entries and accumulated balance to table").into(),
    //                 offset: 0
    //             }
    //         }])
    //     );
    // }

    #[test]
    fn test_valid_solvency_v2_full_prover() {
        const N_USERS: usize = 16;

        // Initialize an empty circuit
        let circuit = SolvencyV2::<N_BYTES_V2, N_USERS, N_ASSETS_V2>::init_empty();

        // Generate a universal trusted setup for testing purposes.
        //
        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the number fo users.
        let (params, pk, vk) = generate_setup_artifacts(K, None, circuit).unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let path = "src/csv/entry_16.csv";

        let (_, entries) = parse_csv_to_entries::<&str, N_ASSETS_V2, N_BYTES_V2>(path).unwrap();

        let circuit = SolvencyV2::<N_BYTES_V2, N_USERS, N_ASSETS_V2>::init(entries);

        let valid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        valid_prover.assert_satisfied();

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit.clone(), vec![vec![]]);

        // let unblinded_commitments: Vec<_> =
        //     proof.commitments.iter().map(|c| c.to_bytes()).collect();

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, vec![vec![]]));
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_solvency_v2_circuit() {
        use plotters::prelude::*;

        let path = "src/merkle_sum_tree/csv/entry_16.csv";

        let (_, entries) = parse_csv_to_entries::<&str, N_ASSETS_V2, N_BYTES_V2>(path).unwrap();

        let circuit = SolvencyV2::<N_BYTES_V2, N_USERS_V2, N_ASSETS_V2>::init(entries);

        let root =
            BitMapBackend::new("prints/solvency-v2-layout.png", (2048, 32768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Summa v2 Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(K, &circuit, &root)
            .unwrap();
    }
}
