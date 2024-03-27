#[cfg(test)]
mod test {

    use crate::circuits::univariate_grand_sum::{
        CircuitConfig, NoRangeCheckConfig, UnivariateGrandSum, UnivariateGrandSumConfig,
    };
    use crate::circuits::utils::{
        compute_h_parallel, full_prover, full_verifier, generate_setup_artifacts,
        open_all_user_points_amortized, open_grand_sums, open_single_user_point_amortized,
        open_user_points, verify_grand_sum_openings, verify_user_inclusion,
    };
    use crate::cryptocurrency::Cryptocurrency;
    use crate::entry::Entry;
    use crate::utils::amortized_kzg::{commit_kzg, create_naive_kzg_proof, verify_kzg_proof};
    use crate::utils::{big_uint_to_fp, parse_csv_to_entries};
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::dev::{FailureLocation, MockProver, VerifyFailure};
    use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
    use halo2_proofs::plonk::{Any, ProvingKey, VerifyingKey};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use num_bigint::BigUint;
    use rand::rngs::OsRng;
    use rand::Rng;

    const K: u32 = 17;
    const N_CURRENCIES: usize = 2;
    const N_USERS: usize = 16;

    #[test]
    fn test_amortized_kzg() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, _, params) =
            set_up::<9, N_USERS, N_CURRENCIES, NoRangeCheckConfig<N_CURRENCIES, N_USERS>>(path);

        let (_, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), &[vec![Fp::zero()]]);

        // Select the first user balance polynomial for the example
        let f_poly = advice_polys.advice_polys.get(1).unwrap();

        let kzg_commitment = commit_kzg(&params, &f_poly);

        // Generate a random user index
        let get_random_user_index = || {
            let user_range: std::ops::Range<usize> = 0..N_USERS;
            OsRng.gen_range(user_range) as usize
        };

        // Open the polynomial at the user index (challenge) using the naive KZG
        let random_user_index = get_random_user_index();
        let challenge = omega.pow_vartime(&[random_user_index as u64]);

        let kzg_proof = create_naive_kzg_proof::<KZGCommitmentScheme<Bn256>>(
            &params,
            pk.get_vk().get_domain(),
            f_poly,
            challenge,
            big_uint_to_fp(&entries[random_user_index].balances()[0]),
        );
        assert!(
            verify_kzg_proof(
                &params,
                kzg_commitment,
                kzg_proof,
                &challenge,
                &big_uint_to_fp(&entries[random_user_index].balances()[0]),
            ),
            "KZG proof verification failed for user {}",
            random_user_index
        );
        assert!(
            !verify_kzg_proof(
                &params,
                kzg_commitment,
                kzg_proof,
                &challenge,
                &big_uint_to_fp(&BigUint::from(123u32)),
            ),
            "Invalid proof verification should fail"
        );

        // Open the polynomial at the user index (challenge) using the amortized KZG

        // Compute the h vector
        let timer = start_timer!(|| "Computing h");
        let h = &compute_h_parallel(&[f_poly.clone()], &params, 0..1)[0];
        end_timer!(timer);

        // Demonstrate a single-challenge opening using the calculated h (FK23, eq. 13)
        let timer = start_timer!(|| "Computing single amortized proof");
        let single_amortized_proof = &open_single_user_point_amortized(&[h], &params, challenge)[0];
        end_timer!(timer);

        assert!(
            *single_amortized_proof == kzg_proof,
            "Single challenge amortized KZG proof is not the same as the naive KZG proof"
        );

        // Compute all openings to the polynomial at once using the amortized KZG approach ("CT" in FK23)
        let timer = start_timer!(|| "Computing all amortized proofs");
        let amortized_openings = &open_all_user_points_amortized(&[h], omega)[0];
        end_timer!(timer);

        // Check that the amortized opening proof for the user is the same as the naive KZG opening proof
        assert!(
            amortized_openings[random_user_index] == kzg_proof,
            "Amortized KZG proof for user {} is not the same as the naive KZG proof",
            random_user_index
        );

        // Verify the amortized KZG opening proof for the user using the same verifier as for the naive KZG proof
        assert!(
            verify_kzg_proof(
                &params,
                kzg_commitment,
                amortized_openings[random_user_index],
                &challenge,
                &big_uint_to_fp(&entries[random_user_index].balances()[0]),
            ),
            "KZG proof verification failed for user {}",
            random_user_index
        );
    }

    #[test]
    fn test_valid_univariate_grand_sum_prover() {
        let path = "../csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<
            N_USERS,
            N_CURRENCIES,
            UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
        >::init(entries.to_vec());

        let valid_prover = MockProver::run(K, &circuit, vec![vec![Fp::zero()]]).unwrap();

        assert_eq!(valid_prover.verify_par(), Ok(()))
    }

    #[test]
    fn test_invalid_instance_value_univariate_grand_sum_prover() {
        let path = "../csv/entry_16.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<
            N_USERS,
            N_CURRENCIES,
            UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
        >::init(entries.to_vec());

        let valid_prover = MockProver::run(K, &circuit, vec![vec![Fp::one()]]).unwrap();

        let invalid_result = valid_prover.verify_par().unwrap_err()[0].to_string();
        assert!(invalid_result.contains("Equality constraint not satisfied"));
    }

    #[test]
    fn test_valid_univariate_grand_sum_full_prover() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, vk, params) =
            set_up::<K, N_USERS, N_CURRENCIES, UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>>(
                path,
            );

        // Calculate total for all entry columns
        let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

        for entry in &entries {
            for (i, balance) in entry.balances().iter().enumerate() {
                csv_total[i] += balance;
            }
        }

        // 1. Proving phase
        // The Custodian generates the ZK-SNARK Halo2 proof that commits to the user entry values in advice polynomials
        // and also range-checks the user balance values
        let (zk_snark_proof, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), &[vec![Fp::zero()]]);

        // Both the Custodian and the Verifier know what column range are the balance columns
        // (The first column is the user IDs)
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian communicates the polynomial length to the Verifier
        let poly_length = 1 << u64::from(K);

        // The Custodian makes a batch opening proof of all user balance polynomials at x = 0 for the Verifier
        let grand_sums_batch_proof = open_grand_sums(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            balance_column_range,
            csv_total
                .iter()
                // The inversion represents the division by the polynomial length (grand total is equal to the constant coefficient times the number of points)
                .map(|x| big_uint_to_fp(&(x)) * Fp::from(poly_length).invert().unwrap())
                .collect::<Vec<Fp>>()
                .as_slice(),
        );

        // The Custodian creates a KZG batch proof of the 4th user ID & balances inclusion
        let user_index = 3_u16;

        let column_range = 0..N_CURRENCIES + 1;
        let openings_batch_proof = open_user_points(
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
        );

        // 2. Verification phase
        // The Verifier verifies the ZK proof
        assert!(full_verifier(
            &params,
            &vk,
            &zk_snark_proof,
            &[vec![Fp::zero()]]
        ));

        // The Verifier is able to independently extract the omega from the verification key
        let omega = pk.get_vk().get_domain().get_omega();

        // The Custodian communicates the polynomial length to the Verifier
        let poly_length = 1 << u64::from(K);

        // Both the Custodian and the Verifier know what column range are the balance columns
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian communicates the KZG batch opening transcript to the Verifier
        // The Verifier verifies the KZG batch opening and calculates the grand sums
        let (verified, grand_sum) = verify_grand_sum_openings::<N_CURRENCIES>(
            &params,
            &zk_snark_proof,
            &grand_sums_batch_proof,
            poly_length,
            balance_column_range,
        );

        assert!(verified);
        for i in 0..N_CURRENCIES {
            assert_eq!(csv_total[i], grand_sum[i]);
        }

        let column_range = 0..N_CURRENCIES + 1;
        // The Verifier verifies the inclusion of the 4th user entry
        let (inclusion_verified, id_and_balance_values) = verify_user_inclusion(
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

    // The prover communicates an invalid omega to the verifier, therefore the opening proof of user inclusion should fail
    #[test]
    fn test_invalid_omega_univariate_grand_sum_proof() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, vk, params) =
            set_up::<K, N_USERS, N_CURRENCIES, UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>>(
                path,
            );

        // 1. Proving phase
        // The Custodian generates the ZK proof
        let (zk_snark_proof, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), &[vec![Fp::zero()]]);

        // The Custodian creates a KZG batch proof of the 4th user ID & balances inclusion
        let user_index = 3_u16;

        let column_range = 0..N_CURRENCIES + 1;
        let openings_batch_proof = open_user_points(
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
        );

        // 2. Verification phase
        // The Verifier verifies the ZK proof
        assert!(full_verifier(
            &params,
            &vk,
            &zk_snark_proof,
            &[vec![Fp::zero()]]
        ));

        // The Verifier is able to independently extract the omega from the verification key
        let omega = pk.get_vk().get_domain().get_omega();

        // Both the Custodian and the Verifier know what column range are the balance columns
        let balance_column_range = 1..N_CURRENCIES + 1;

        // Test failure case with the wrong group generator
        // Slightly modify the generator
        let bad_omega = omega.sub(&Fp::one());
        let (balances_verified, _) = verify_user_inclusion(
            &params,
            &zk_snark_proof,
            &openings_batch_proof,
            balance_column_range,
            bad_omega,
            user_index,
        );
        //The verification should fail
        assert!(!balances_verified);
    }

    // The prover communicates an invalid polynomial length to the verifier (smaller than the actual length). This will result in a different grand sum
    #[test]
    fn test_invalid_poly_length_univariate_grand_sum_full_prover() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, vk, params) =
            set_up::<K, N_USERS, N_CURRENCIES, UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>>(
                path,
            );

        // Calculate total for all entry columns
        let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

        for entry in &entries {
            for (i, balance) in entry.balances().iter().enumerate() {
                csv_total[i] += balance;
            }
        }

        // 1. Proving phase
        // The Custodian generates the ZK-SNARK Halo2 proof that commits to the user entry values in advice polynomials
        // and also range-checks the user balance values
        let (zk_snark_proof, advice_polys, _) =
            full_prover(&params, &pk, circuit.clone(), &[vec![Fp::zero()]]);

        // Both the Custodian and the Verifier know what column range are the balance columns
        // (The first column is the user IDs)
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian communicates the polynomial length to the Verifier
        let poly_length = 1 << u64::from(K);

        // The Custodian makes a batch opening proof of all user balance polynomials at x = 0 for the Verifier
        let grand_sums_batch_proof = open_grand_sums(
            &advice_polys.advice_polys,
            &advice_polys.advice_blinds,
            &params,
            balance_column_range,
            csv_total
                .iter()
                .map(|x| big_uint_to_fp(&(x)) * Fp::from(poly_length).invert().unwrap())
                .collect::<Vec<Fp>>()
                .as_slice(),
        );

        // 2. Verification phase
        // The Verifier verifies the ZK proof
        assert!(full_verifier(
            &params,
            &vk,
            &zk_snark_proof,
            &[vec![Fp::zero()]]
        ));

        // The Custodian communicates the (invalid) polynomial length to the Verifier
        let invalid_poly_length = 2 ^ u64::from(K) - 1;

        // Both the Custodian and the Verifier know what column range are the balance columns
        let balance_column_range = 1..N_CURRENCIES + 1;

        // The Custodian communicates the KZG batch opening transcript to the Verifier
        // The Verifier verifies the KZG batch opening and calculates the grand sums
        let (verified, grand_sum) = verify_grand_sum_openings::<N_CURRENCIES>(
            &params,
            &zk_snark_proof,
            &grand_sums_batch_proof,
            invalid_poly_length,
            balance_column_range,
        );

        // The opened grand sum is not equal to the actual sum of balances extracted from the csv file
        assert!(verified);
        for i in 0..N_CURRENCIES {
            assert_ne!(csv_total[i], grand_sum[i]);
        }
    }

    // Building a proof using as input a csv file with an entry that is not in range [0, 2^64 - 1] should fail the range check constraint on the leaf balance
    #[test]
    fn test_balance_not_in_range() {
        let path = "../csv/entry_16_overflow.csv";

        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];
        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<
            N_USERS,
            N_CURRENCIES,
            UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
        >::init(entries.to_vec());

        let invalid_prover = MockProver::run(K, &circuit, vec![vec![Fp::zero()]]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (2, "Perform range check on balance 0 of user 0").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (6, "Perform range check on balance 0 of user 2").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 10).into(),
                    location: FailureLocation::InRegion {
                        region: (3, "Perform range check on balance 1 of user 0").into(),
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

        let circuit = UnivariateGrandSum::<
            N_USERS,
            N_CURRENCIES,
            UnivariateGrandSumConfig<N_CURRENCIES, N_USERS>,
        >::init(entries);

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

    fn set_up<
        const K: u32,
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    >(
        path: &str,
    ) -> (
        Vec<Entry<N_CURRENCIES>>,
        UnivariateGrandSum<N_USERS, N_CURRENCIES, CONFIG>,
        ProvingKey<G1Affine>,
        VerifyingKey<G1Affine>,
        ParamsKZG<Bn256>,
    )
    where
        [(); N_CURRENCIES + 1]:,
    {
        // Initialize an empty circuit
        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES, CONFIG>::init_empty();

        // Generate a universal trusted setup for testing purposes.
        //
        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the number fo users.
        let (params, pk, vk) = generate_setup_artifacts(K, None, &circuit).unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
        let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

        parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES, CONFIG>::init(entries.to_vec());

        (entries, circuit, pk, vk, params)
    }
}
