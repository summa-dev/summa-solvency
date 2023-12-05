#[cfg(test)]
mod test {

    use crate::circuits::solvency_v2::SolvencyV2;
    use crate::circuits::utils::{
        full_prover, full_verifier, generate_setup_artifacts, open_grand_sums, open_user_balances,
        verify_grand_sum_openings, verify_user_inclusion,
    };
    use crate::cryptocurrency::Cryptocurrency;
    use crate::entry::Entry;
    use crate::utils::parse_csv_to_entries;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };
    use num_bigint::BigUint;

    const K: u32 = 9;

    const N_BYTES: usize = 8;
    const N_CURRENCIES: usize = 2;
    const N_USERS: usize = 16;

    #[test]
    fn test_valid_solvency_v2() {
        let path = "src/csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        let _ =
            parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(path, &mut entries, &mut cryptos)
                .unwrap();

        let circuit = SolvencyV2::<N_BYTES, N_USERS, N_CURRENCIES>::init(entries.to_vec());

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
        let circuit = SolvencyV2::<N_BYTES, N_USERS, N_CURRENCIES>::init_empty();

        // Generate a universal trusted setup for testing purposes.
        //
        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the number fo users.
        let (params, pk, vk) = generate_setup_artifacts(K, None, circuit).unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let path = "src/csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

        let _ =
            parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(path, &mut entries, &mut cryptos)
                .unwrap();

        // Calculate total for all entry columns
        let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

        for entry in &entries {
            for (i, balance) in entry.balances().iter().enumerate() {
                csv_total[i] += balance;
            }
        }

        let circuit = SolvencyV2::<N_BYTES, N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let valid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        valid_prover.assert_satisfied();

        // 1. Proving phase
        // The Custodian generates the ZK proof
        let (zk_snark_proof, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), vec![vec![]]);

        // Both the Custodian and the Verifier know what column range are the balance columns
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian makes an opening at x = 0 for the Verifier
        // (The first column is the user IDs)
        let kzg_proofs = open_grand_sums::<N_CURRENCIES>(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            balance_column_range,
        );

        // The Custodian creates a KZG proof of the 4th user balances inclusion
        let user_index = 3_u16;

        let balance_column_range = 1..N_CURRENCIES + 1;
        let balance_opening_proofs = open_user_balances::<N_CURRENCIES>(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            balance_column_range,
            omega,
            user_index,
        );

        // 2. Verification phase
        // The Verifier verifies the ZK proof
        assert!(full_verifier(&params, &vk, &zk_snark_proof, vec![vec![]]));

        // The Verifier is able to independently extract the omega from the verification key
        let omega = pk.get_vk().get_domain().get_omega();

        // The Custodian communicates the polynomial degree to the Verifier
        let poly_degree = u64::try_from(advice_polys.advice_polys[0].len()).unwrap();

        // Both the Custodian and the Verifier know what column range are the balance columns
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian communicates the KZG opening transcripts to the Verifier
        // The Verifier verifies the KZG opening transcripts and calculates the grand sums
        let (verified, grand_sum) = verify_grand_sum_openings::<N_CURRENCIES>(
            &params,
            &zk_snark_proof,
            kzg_proofs,
            poly_degree,
            balance_column_range,
        );

        for i in 0..N_CURRENCIES {
            assert!(verified[i]);
            assert_eq!(csv_total[i], grand_sum[i]);
        }

        let balance_column_range = 1..N_CURRENCIES + 1;
        let (balances_verified, balance_values) = verify_user_inclusion::<N_CURRENCIES>(
            &params,
            &zk_snark_proof,
            balance_opening_proofs,
            balance_column_range,
            omega,
            user_index,
        );

        let fourth_user_csv_entry = entries.get(user_index as usize).unwrap();
        for i in 0..N_CURRENCIES {
            assert!(balances_verified[i]);
            assert_eq!(
                *fourth_user_csv_entry.balances().get(i).unwrap(),
                balance_values[i]
            );
        }
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_solvency_v2_circuit() {
        use plotters::prelude::*;

        let path = "src/merkle_sum_tree/csv/entry_16.csv";

        let (_, entries) = parse_csv_to_entries::<&str, N_CURRENCIES, N_BYTES>(path).unwrap();

        let circuit = SolvencyV2::<N_BYTES, N_USERS, N_CURRENCIES>::init(entries);

        let root =
            BitMapBackend::new("prints/solvency-v2-layout.png", (2048, 32768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Summa v2 Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(K, &circuit, &root)
            .unwrap();
    }
}
