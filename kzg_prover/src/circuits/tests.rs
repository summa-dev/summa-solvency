#[cfg(test)]
mod test {

    use crate::circuits::univariate_grand_sum::UnivariateGrandSum;
    use crate::circuits::utils::{
        full_prover, full_verifier, generate_setup_artifacts, open_grand_sums, open_user_points,
        verify_grand_sum_openings, verify_user_inclusion,
    };
    use crate::cryptocurrency::Cryptocurrency;
    use crate::entry::Entry;
    use crate::utils::batched_kzg::{
        commit_kzg, compute_h, create_standard_kzg_proof, verify_kzg_proof,
    };
    use crate::utils::{big_uint_to_fp, parse_csv_to_entries};
    use halo2_proofs::arithmetic::{best_fft, Field};
    use halo2_proofs::dev::{FailureLocation, MockProver, VerifyFailure};
    use halo2_proofs::halo2curves::bn256::{Bn256, Fr as Fp, G1Affine};
    use halo2_proofs::halo2curves::group::Curve;
    use halo2_proofs::plonk::{Any, ProvingKey, VerifyingKey};
    use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
    use halo2_proofs::poly::EvaluationDomain;
    use num_bigint::BigUint;

    const K: u32 = 9;
    const N_CURRENCIES: usize = 2;
    const N_USERS: usize = 16;

    #[test]
    fn test_batched_kzg() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, _, params) = set_up::<N_USERS, N_CURRENCIES>(path);

        let (_, advice_polys, omega) = full_prover(&params, &pk, circuit.clone(), &[vec![]]);

        let f_poly = advice_polys.advice_polys.get(1).unwrap();

        // Double the polynomial length, thus K + 1
        let double_domain = EvaluationDomain::new(1, K + 1);
        let mut h = compute_h(&params, f_poly, &double_domain);

        let kzg_commitment = commit_kzg(&params, &f_poly);

        // Open the polynomial at X = omega^1 (user 1) using the standard KZG
        let challenge = omega;
        let kzg_proof = create_standard_kzg_proof::<KZGCommitmentScheme<Bn256>>(
            &params,
            pk.get_vk().get_domain(),
            f_poly,
            challenge,
        );

        assert!(
            verify_kzg_proof(
                &params,
                kzg_commitment,
                kzg_proof,
                &challenge,
                &big_uint_to_fp(&entries[1].balances()[0]),
            ),
            "KZG proof verification failed"
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
        println!("KZG proof verified");

        // Compute all openings to the polynomial using the amortized KZG approach (FK23)
        best_fft(&mut h, omega, f_poly.len().trailing_zeros());

        // Check that the amortized opening proof for user #1 is the same as the naive KZG opening proof
        assert!(
            h[1].to_affine() == kzg_proof.to_affine(),
            "Amortized KZG proof for user 1 is not the same as the standard KZG proof"
        );

        // Verify the amortized KZG opening proof for user #1
        assert!(
            verify_kzg_proof(
                &params,
                kzg_commitment,
                h[1],
                &challenge,
                &big_uint_to_fp(&entries[1].balances()[0]),
            ),
            "KZG proof verification failed"
        );
    }

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
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, vk, params) = set_up::<N_USERS, N_CURRENCIES>(path);

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
            full_prover(&params, &pk, circuit.clone(), &[vec![]]);

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
        assert!(full_verifier(&params, &vk, &zk_snark_proof, &[vec![]]));

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

    // The prover communicates an invalid omega to the verifier, therefore the opening proof of user inclusion should fail
    #[test]
    fn test_invalid_omega_univariate_grand_sum_proof() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, vk, params) = set_up::<N_USERS, N_CURRENCIES>(path);

        // 1. Proving phase
        // The Custodian generates the ZK proof
        let (zk_snark_proof, advice_polys, omega) =
            full_prover(&params, &pk, circuit.clone(), &[vec![]]);

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
        assert!(full_verifier(&params, &vk, &zk_snark_proof, &[vec![]]));

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
    }

    // The prover communicates an invalid polynomial length to the verifier (smaller than the actual length). This will result in a different grand sum
    #[test]
    fn test_invalid_poly_length_univariate_grand_sum_full_prover() {
        let path = "../csv/entry_16.csv";

        let (entries, circuit, pk, vk, params) = set_up::<N_USERS, N_CURRENCIES>(path);

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
            full_prover(&params, &pk, circuit.clone(), &[vec![]]);

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
        assert!(full_verifier(&params, &vk, &zk_snark_proof, &[vec![]]));

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

    fn set_up<const N_USERS: usize, const N_CURRENCIES: usize>(
        path: &str,
    ) -> (
        Vec<Entry<N_CURRENCIES>>,
        UnivariateGrandSum<N_USERS, N_CURRENCIES>,
        ProvingKey<G1Affine>,
        VerifyingKey<G1Affine>,
        ParamsKZG<Bn256>,
    )
    where
        [(); N_CURRENCIES + 1]:,
    {
        // Initialize an empty circuit
        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();

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

        let circuit = UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

        (entries, circuit, pk, vk, params)
    }
}
