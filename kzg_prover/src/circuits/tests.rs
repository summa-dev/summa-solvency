#[cfg(test)]
mod test {

    use crate::circuits::univariate_grand_sum::UnivariateGrandSum;
    use crate::circuits::utils::{
        full_prover, full_verifier, generate_setup_artifacts, open_grand_sums, open_user_points,
        verify_grand_sum_openings, verify_user_inclusion,
    };
    use crate::cryptocurrency::Cryptocurrency;
    use crate::entry::Entry;
    use crate::utils::parse_csv_to_entries;
    use halo2_proofs::dev::{FailureLocation, MockProver, VerifyFailure};
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::Any;
    use num_bigint::BigUint;

    const K: u32 = 17;
    const N_CURRENCIES: usize = 2;
    const N_USERS: usize = 16;

    #[test]
    fn test_valid_univariate_grand_sum_prover() {
        let path = "../csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let valid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        assert_eq!(valid_prover.verify_par(), Ok(()))
    }

    #[test]
    fn test_valid_univariate_grand_sum_full_prover() {
        const N_USERS: usize = 16;

        // Initialize an empty circuit
        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();

        // Generate a universal trusted setup for testing purposes.
        //
        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the number fo users.
        let (params, pk, vk) = generate_setup_artifacts(K, None, circuit).unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let path = "../csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

        let _ =
            parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        // Calculate total for all entry columns
        let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

        for entry in &entries {
            for (i, balance) in entry.balances().iter().enumerate() {
                csv_total[i] += balance;
            }
        }

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let valid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        valid_prover.assert_satisfied();

        // 1. Proving phase
        // The Custodian generates the ZK-SNARK Halo2 proof that commits to the user entry values in advice polynomials
        // and also range-checks the user balance values
        let (zk_snark_proof, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), vec![vec![]]);

        // Both the Custodian and the Verifier know what column range are the balance columns
        // (The first column is the user IDs)
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian makes a batch opening proof of all user balance polynomials at x = 0 for the Verifier
        let grand_sums_batch_proof = open_grand_sums::<N_CURRENCIES>(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            balance_column_range,
        );

        // The Custodian creates a KZG batch proof of the 4th user ID & balances inclusion
        let user_index = 3_u16;

        let column_range = 0..N_CURRENCIES + 1;
        let openings_batch_proof = open_user_points::<N_CURRENCIES>(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            column_range,
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

        // The Custodian communicates the KZG batch opening transcript to the Verifier
        // The Verifier verifies the KZG batch opening and calculates the grand sums
        let (verified, grand_sum) = verify_grand_sum_openings::<N_CURRENCIES>(
            &params,
            &zk_snark_proof,
            grand_sums_batch_proof,
            poly_degree,
            balance_column_range,
        );

        assert!(verified);
        for i in 0..N_CURRENCIES {
            assert_eq!(csv_total[i], grand_sum[i]);
        }

        let column_range = 0..N_CURRENCIES + 1;
        // The Verifier verifies the inclusion of the 4th user entry
        const N_POINTS: usize = N_CURRENCIES + 1;
        let (inclusion_verified, id_and_balance_values) = verify_user_inclusion::<N_POINTS>(
            &params,
            &zk_snark_proof,
            &openings_batch_proof,
            column_range,
            omega,
            user_index,
        );

        assert!(inclusion_verified);
        let fourth_user_csv_entry = entries.get(user_index as usize).unwrap();
        for i in 0..N_CURRENCIES + 1 {
            if i == 0 {
                assert_eq!(
                    *fourth_user_csv_entry.username_as_big_uint(),
                    id_and_balance_values[i]
                );
            } else {
                assert_eq!(
                    *fourth_user_csv_entry.balances().get(i - 1).unwrap(),
                    id_and_balance_values[i]
                );
            }
        }
    }

    #[test]
    fn test_invalid_univariate_grand_sum_proof() {
        const N_USERS: usize = 16;

        // Initialize an empty circuit
        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();

        // Generate a universal trusted setup for testing purposes.
        //
        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the number fo users.
        let (params, pk, vk) = generate_setup_artifacts(K, None, circuit).unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let path = "../csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        // Calculate total for all entry columns
        let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

        for entry in &entries {
            for (i, balance) in entry.balances().iter().enumerate() {
                csv_total[i] += balance;
            }
        }

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let valid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        valid_prover.assert_satisfied();

        // 1. Proving phase
        // The Custodian generates the ZK proof
        let (zk_snark_proof, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), vec![vec![]]);

        // The Custodian creates a KZG batch proof of the 4th user ID & balances inclusion
        let user_index = 3_u16;

        let column_range = 0..N_CURRENCIES + 1;
        let openings_batch_proof = open_user_points::<N_CURRENCIES>(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            column_range,
            omega,
            user_index,
        );

        // 2. Verification phase
        // The Verifier verifies the ZK proof
        assert!(full_verifier(&params, &vk, &zk_snark_proof, vec![vec![]]));

        // The Verifier is able to independently extract the omega from the verification key
        let omega = pk.get_vk().get_domain().get_omega();

        // Both the Custodian and the Verifier know what column range are the balance columns
        let balance_column_range = 1..N_CURRENCIES + 1;

        // Test failure case with the wrong group generator
        // Slightly modify the generator
        let bad_omega = omega.sub(&Fp::one());
        let (balances_verified, _) = verify_user_inclusion::<N_CURRENCIES>(
            &params,
            &zk_snark_proof,
            &openings_batch_proof,
            balance_column_range,
            bad_omega,
            user_index,
        );
        //The verification should fail
        assert!(!balances_verified);

        // TODO add more negative tests
    }

    // Building a proof using as input a csv file with an entry that is not in range [0, 2^N_BYTES*8 - 1] should fail the range check constraint on the leaf balance
    #[test]
    fn test_balance_not_in_range() {
        let path = "../csv/entry_16_overflow.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        let invalid_prover = MockProver::run(K, &circuit, vec![vec![]]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Fixed, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 65536 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Fixed, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 65539 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (2, "Perform range check on balance 0 of user 0").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 10).into(),
                    location: FailureLocation::InRegion {
                        region: (5, "Perform range check on balance 1 of user 1").into(),
                        offset: 0
                    }
                },
            ])
        );
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_univariate_grand_sum_circuit() {
        use plotters::prelude::*;

        let path = "../csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        let _ =
            parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries);

        let root = BitMapBackend::new("prints/univariate-grand-sum-layout.png", (2048, 32768))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Univariate Grand Sum Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(K, &circuit, &root)
            .unwrap();
    }
}
