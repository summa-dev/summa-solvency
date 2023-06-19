#[cfg(test)]
mod test {

    use crate::circuits::{
        aggregation::WrappedAggregationCircuit,
        merkle_sum_tree::MstInclusionCircuit,
        // solvency::SolvencyCircuit,
        utils::{full_prover, full_verifier, generate_setup_params},
    };
    use crate::merkle_sum_tree::{MST_WIDTH, N_ASSETS};
    use ark_std::{end_timer, start_timer};
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::{keygen_pk, keygen_vk, Any, Circuit},
        poly::commitment::Params,
    };
    use rand::rngs::OsRng;
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
        gen_pk,
        halo2::gen_snark_shplonk,
        CircuitExt,
    };

    const LEVELS: usize = 4;

    #[test]
    fn test_standard_on_chain_verifier() {
        let params = generate_setup_params(11);

        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let pk = gen_pk(&params, &circuit, None);

        let num_instances = circuit.num_instance();
        let instances = circuit.instances();

        let proof_calldata = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());

        let deployment_code = gen_evm_verifier_shplonk::<
            MstInclusionCircuit<LEVELS, MST_WIDTH, N_ASSETS>,
        >(&params, pk.get_vk(), num_instances, None);

        let gas_cost = evm_verify(deployment_code, instances, proof_calldata);

        // assert gas_cost to verify the proof on chain to be between 575000 and 590000
        assert!(
            (0..=600000).contains(&gas_cost),
            "gas_cost is not within the expected range"
        );
    }

    #[test]
    fn test_valid_merkle_sum_tree() {
        for user_index in 0..16 {
            let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
                "src/merkle_sum_tree/csv/entry_16.csv",
                user_index,
            );

            let valid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

            valid_prover.assert_satisfied();
        }
    }

    #[test]
    fn test_valid_merkle_sum_tree_2() {
        // Same as above but now the entries contain a balance that is greater than 64 bits
        // liabilities sum is 18446744073710096590

        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        assert_eq!(circuit.instances()[0].len(), circuit.num_instance()[0]);

        let valid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

        valid_prover.assert_satisfied();
    }

    #[test]
    fn test_valid_merkle_sum_tree_with_full_prover() {
        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

        // we generate a universal trusted setup of our own for testing
        let params = generate_setup_params(11);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        // Note: the dimension of the circuit used to generate the keys must be the same as the dimension of the circuit used to generate the proof
        // In this case, the dimension are represented by the heigth of the merkle tree
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit.clone(), circuit.instances());

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, circuit.instances()));
    }

    #[test]
    #[ignore]
    fn test_valid_merkle_sum_tree_with_full_recursive_prover() {
        // params for the aggregation circuit
        let params_agg = generate_setup_params(23);

        // downsize params for our application specific snark
        let mut params_app = params_agg.clone();
        params_app.downsize(11);

        // generate the verification key and the proving key for the application circuit, using an empty circuit
        let circuit_app = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

        let vk_app = keygen_vk(&params_app, &circuit_app).expect("vk generation should not fail");
        let pk_app =
            keygen_pk(&params_app, vk_app, &circuit_app).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit_app = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let snark_app = [(); 1]
            .map(|_| gen_snark_shplonk(&params_app, &pk_app, circuit_app.clone(), None::<&str>));

        const N_SNARK: usize = 1;

        // create aggregation circuit
        let agg_circuit = WrappedAggregationCircuit::<N_SNARK>::new(&params_agg, snark_app);

        assert_eq!(agg_circuit.instances()[0], circuit_app.instances()[0]);

        let start0 = start_timer!(|| "gen vk & pk");
        // generate proving key for the aggregation circuit
        let pk_agg = gen_pk(&params_agg, &agg_circuit.without_witnesses(), None);
        end_timer!(start0);

        let num_instances = agg_circuit.num_instance();
        let instances = agg_circuit.instances();

        let proof_calldata =
            gen_evm_proof_shplonk(&params_agg, &pk_agg, agg_circuit, instances.clone());

        let deployment_code = gen_evm_verifier_shplonk::<WrappedAggregationCircuit<N_SNARK>>(
            &params_agg,
            pk_agg.get_vk(),
            num_instances,
            None,
        );
        let gas_cost = evm_verify(deployment_code, instances, proof_calldata);

        // assert gas_cost to verify the proof on chain to be between 575000 and 590000
        assert!(
            (575000..=590000).contains(&gas_cost),
            "gas_cost is not within the expected range"
        );
    }

    #[test]
    #[ignore]
    fn test_invalid_merkle_sum_tree_with_full_recursive_prover() {
        // params for the aggregation circuit
        let params_agg = generate_setup_params(23);

        // downsize params for our application specific snark
        let mut params_app = params_agg.clone();
        params_app.downsize(11);

        // generate the verification key and the proving key for the application circuit, using an empty circuit
        let circuit_app = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

        let vk_app = keygen_vk(&params_app, &circuit_app).expect("vk generation should not fail");
        let pk_app =
            keygen_pk(&params_app, vk_app, &circuit_app).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit_app = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let snark_app = [(); 1]
            .map(|_| gen_snark_shplonk(&params_app, &pk_app, circuit_app.clone(), None::<&str>));

        const N_SNARK: usize = 1;

        // create aggregation circuit
        let agg_circuit = WrappedAggregationCircuit::<N_SNARK>::new(&params_agg, snark_app);

        let invalid_root_hash = Fp::from(1000u64);

        let mut agg_circuit_invalid_instances = agg_circuit.instances();
        agg_circuit_invalid_instances[0][1] = invalid_root_hash;

        let invalid_prover =
            MockProver::run(23, &agg_circuit, agg_circuit_invalid_instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "").into(),
                        offset: 1
                    }
                }
            ])
        );
    }

    // Passing an invalid root hash in the instance column should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_root_hash() {
        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let mut instances = circuit.instances();
        let invalid_root_hash = Fp::from(1000u64);
        instances[0][1] = invalid_root_hash;

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (31, "permute state").into(),
                        offset: 43
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    #[test]
    fn test_invalid_root_hash_as_instance_with_full_prover() {
        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init_empty();

        // we generate a universal trusted setup of our own for testing
        let params = generate_setup_params(11);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let invalid_root_hash = Fp::from(1000u64);

        let mut instances = circuit.instances();
        instances[0][1] = invalid_root_hash;

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, instances.clone());

        // verify the proof to be false
        assert!(!full_verifier(&params, &vk, proof, instances));
    }

    // Passing an invalid leaf hash as input for the witness generation should fail:
    // - the permutation check between the leaf hash and the instance column leaf hash
    // - the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_hash_as_witness() {
        let mut circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let instances = circuit.instances();

        // invalidate leaf hash
        circuit.leaf_hash = Fp::from(1000u64);

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (31, "permute state").into(),
                        offset: 43
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    // Passing an invalid leaf hash in the instance column should fail the permutation check between the (valid) leaf hash added as part of the witness and the instance column leaf hash
    #[test]
    fn test_invalid_leaf_hash_as_instance() {
        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let mut instances = circuit.instances();
        let invalid_leaf_hash = Fp::from(1000u64);
        instances[0][0] = invalid_leaf_hash;

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
            ])
        );
    }

    // Passing an invalid leaf balance as input for the witness generation.
    // Invalid leaf balance means: leaf_hash = H(user_id, valid_balance), while the leaf balance passed as witness is invalid.
    // The following permutation check should fail:
    // - The root hash that doesn't match the expected one.
    #[test]
    fn test_invalid_leaf_balance_as_witness() {
        let mut circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        // We need to extract the valid instances before invalidating the circuit
        let instances = circuit.instances();

        // invalid leaf balance for the first asset
        circuit.leaf_balances = vec![Fp::from(1000u64), circuit.leaf_balances[1]];

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (31, "permute state").into(),
                        offset: 43
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                }
            ])
        );

        let mut circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        // We need to extract the valid instances before invalidating the circuit
        let instances = circuit.instances();

        // invalid leaf balance for the second asset
        circuit.leaf_balances = vec![circuit.leaf_balances[0], Fp::from(1000u64)];

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (31, "permute state").into(),
                        offset: 43
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    // Passing a non binary index should fail the bool constraint check and the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_non_binary_index() {
        let mut circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let instances = circuit.instances();

        // invalidate path index inside the circuit
        circuit.path_indices[0] = Fp::from(2);

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "bool constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::advice(), 8).into(), 0).into(), "0x2".to_string()),]
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (31, "permute state").into(),
                        offset: 43
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    // Swapping the indices should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_swapping_index() {
        let mut circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let instances = circuit.instances();

        // swap indices
        circuit.path_indices[0] = Fp::from(1);

        let invalid_prover = MockProver::run(11, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (31, "permute state").into(),
                        offset: 43
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    // // Passing assets_sum that are less than the liabilities sum should not fail the solvency circuit
    // #[test]
    // fn test_valid_liabilities_less_than_assets() {
    //     // Make the first asset sum more than liabilities sum (556862)
    //     let assets_sum = [Fp::from(556863u64), Fp::from(556863u64)];

    //     let circuit = SolvencyCircuit::<MST_WIDTH, N_ASSETS>::init(
    //         assets_sum,
    //         "src/merkle_sum_tree/csv/entry_16.csv",
    //     );

    //     let valid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

    //     valid_prover.assert_satisfied();
    // }

    // // Passing assets sum that is less than the liabilities sum should fail the solvency circuit
    // #[test]
    // fn test_invalid_assets_less_than_liabilities() {
    //     // Make the first asset sum less than liabilities sum (556862)
    //     let less_than_assets_sum_1st = [Fp::from(556861u64), Fp::from(556863u64)];

    //     let circuit = SolvencyCircuit::<MST_WIDTH, N_ASSETS>::init(
    //         less_than_assets_sum_1st,
    //         "src/merkle_sum_tree/csv/entry_16.csv",
    //     );

    //     let invalid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

    //     assert_eq!(
    //         invalid_prover.verify(),
    //         Err(vec![VerifyFailure::ConstraintNotSatisfied {
    //             constraint: ((8, "is_lt is 1").into(), 0, "").into(),
    //             location: FailureLocation::InRegion {
    //                 region: (11, "enforce sum to be less than total assets").into(),
    //                 offset: 0
    //             },
    //             cell_values: vec![
    //                 // The zero means that is not less than
    //                 (((Any::advice(), 49).into(), 0).into(), "0".to_string())
    //             ]
    //         }])
    //     );

    //     // Make the second asset sum less than liabilities sum (556862)
    //     let less_than_assets_sum_2nd = [Fp::from(556863u64), Fp::from(556861u64)];

    //     let circuit = SolvencyCircuit::<MST_WIDTH, N_ASSETS>::init(
    //         less_than_assets_sum_2nd,
    //         "src/merkle_sum_tree/csv/entry_16.csv",
    //     );

    //     let invalid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

    //     assert_eq!(
    //         invalid_prover.verify(),
    //         Err(vec![VerifyFailure::ConstraintNotSatisfied {
    //             constraint: ((8, "is_lt is 1").into(), 0, "").into(),
    //             location: FailureLocation::InRegion {
    //                 region: (12, "enforce sum to be less than total assets").into(),
    //                 offset: 0
    //             },
    //             cell_values: vec![
    //                 // The zero means that is not less than
    //                 (((Any::advice(), 49).into(), 0).into(), "0".to_string())
    //             ]
    //         }])
    //     );

    //     // Make both the balances less than liabilities sum (556862)
    //     let less_than_assets_sum_both = [Fp::from(556861u64), Fp::from(556861u64)];

    //     let circuit = SolvencyCircuit::<MST_WIDTH, N_ASSETS>::init(
    //         less_than_assets_sum_both,
    //         "src/merkle_sum_tree/csv/entry_16.csv",
    //     );

    //     let invalid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

    //     assert_eq!(
    //         invalid_prover.verify(),
    //         Err(vec![
    //             VerifyFailure::ConstraintNotSatisfied {
    //                 constraint: ((8, "is_lt is 1").into(), 0, "").into(),
    //                 location: FailureLocation::InRegion {
    //                     region: (11, "enforce sum to be less than total assets").into(),
    //                     offset: 0
    //                 },
    //                 cell_values: vec![
    //                     // The zero means that is not less than
    //                     (((Any::advice(), 49).into(), 0).into(), "0".to_string())
    //                 ]
    //             },
    //             VerifyFailure::ConstraintNotSatisfied {
    //                 constraint: ((8, "is_lt is 1").into(), 0, "").into(),
    //                 location: FailureLocation::InRegion {
    //                     region: (12, "enforce sum to be less than total assets").into(),
    //                     offset: 0
    //                 },
    //                 cell_values: vec![
    //                     // The zero means that is not less than
    //                     (((Any::advice(), 49).into(), 0).into(), "0".to_string())
    //                 ]
    //             }
    //         ])
    //     );
    // }

    // // Manipulating the liabilities to make it less than the assets sum should fail the solvency circuit because the root hash will not match
    // #[test]
    // fn test_invalid_manipulated_liabilties() {
    //     // For the second asset, the assets_sum is less than the liabilities sum (556862)
    //     let less_than_assets_sum_2nd = [Fp::from(556863u64), Fp::from(556861u64)];

    //     let mut circuit = SolvencyCircuit::<MST_WIDTH, N_ASSETS>::init(
    //         less_than_assets_sum_2nd,
    //         "src/merkle_sum_tree/csv/entry_16.csv",
    //     );

    //     // But actually, the CEX tries to manipulate the liabilities sum for the second asset to make it less than the assets sum
    //     circuit.left_node_balances[1] = Fp::from(1u64);

    //     // This should pass the less than constraint but generate a root hash that does not match the one passed in the instance
    //     let invalid_prover = MockProver::run(11, &circuit, circuit.instances()).unwrap();

    //     assert_eq!(
    //         invalid_prover.verify(),
    //         Err(vec![
    //             VerifyFailure::Permutation {
    //                 column: (Any::Instance, 0).into(),
    //                 location: FailureLocation::OutsideRegion { row: 0 }
    //             },
    //             VerifyFailure::Permutation {
    //                 column: (Any::advice(), 42).into(),
    //                 location: FailureLocation::InRegion {
    //                     region: (4, "permute state").into(),
    //                     offset: 43
    //                 }
    //             }
    //         ])
    //     );
    // }

    use crate::circuits::ecdsa::EcdsaVerifyCircuit;
    use ecc::maingate::{big_to_fe, decompose, fe_to_big};
    use halo2_proofs::arithmetic::{CurveAffine, Field};
    use halo2_proofs::halo2curves::{
        ff::PrimeField, group::Curve, secp256k1::Secp256k1Affine as Secp256k1,
    };

    fn mod_n(x: <Secp256k1 as CurveAffine>::Base) -> <Secp256k1 as CurveAffine>::ScalarExt {
        let x_big = fe_to_big(x);
        big_to_fe(x_big)
    }

    #[test]
    fn test_ecdsa_valid_verifier() {
        let g = Secp256k1::generator();

        // Generate a key pair (sk, pk)
        // sk is a random scalar (exists within the scalar field, which is the order of the group generated by g
        // Note that the scalar field is different from the prime field of the curve.
        // pk is a point on the curve
        let sk = <Secp256k1 as CurveAffine>::ScalarExt::random(OsRng);

        let public_key = (g * sk).to_affine();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::random(OsRng);

        // Draw arandomness -> k is also a scalar living in the order of the group generated by generator point g.
        let k = <Secp256k1 as CurveAffine>::ScalarExt::random(OsRng);
        let k_inv = k.invert().unwrap();

        let r_point = (g * k).to_affine().coordinates().unwrap();
        let x = r_point.x();

        // perform r mod n to ensure that r is a valid scalar
        let r = mod_n(*x);

        let s = k_inv * (msg_hash + (r * sk));

        // Sanity check. Ensure we construct a valid signature. So lets verify it
        {
            let s_inv = s.invert().unwrap();
            let u_1 = msg_hash * s_inv;
            let u_2 = r * s_inv;
            let r_point = ((g * u_1) + (public_key * u_2))
                .to_affine()
                .coordinates()
                .unwrap();
            let x_candidate = r_point.x();
            let r_candidate = mod_n(*x_candidate);
            assert_eq!(r, r_candidate);
        }

        let circuit = EcdsaVerifyCircuit::init(public_key, r, s, msg_hash);

        let valid_prover = MockProver::run(18, &circuit, circuit.instances()).unwrap();

        valid_prover.assert_satisfied();
    }

    // signature input obtained from an actual signer => https://gist.github.com/enricobottazzi/58c52754cabd8dd8e7ee9ed5d7591814
    const SECRET_KEY: [u8; 32] = [
        154, 213, 29, 179, 82, 32, 97, 124, 125, 25, 241, 239, 17, 36, 119, 73, 209, 25, 253, 111,
        255, 254, 166, 249, 243, 69, 250, 217, 23, 156, 1, 61,
    ];

    const R: [u8; 32] = [
        239, 76, 20, 99, 168, 118, 101, 14, 199, 216, 110, 228, 253, 132, 166, 78, 13, 120, 59,
        128, 32, 197, 192, 196, 58, 157, 69, 172, 73, 244, 76, 202,
    ];

    const S: [u8; 32] = [
        68, 27, 200, 44, 31, 175, 180, 124, 55, 112, 24, 91, 32, 136, 237, 17, 71, 137, 28, 120,
        126, 52, 175, 114, 197, 239, 156, 80, 112, 115, 237, 79,
    ];

    const MSG_HASH: [u8; 32] = [
        115, 139, 142, 103, 234, 97, 224, 87, 102, 70, 65, 216, 226, 136, 248, 62, 44, 36, 172,
        170, 253, 70, 103, 220, 126, 83, 27, 233, 159, 149, 214, 28,
    ];

    #[test]
    fn test_ecdsa_no_random_valid() {
        let secret_key = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(SECRET_KEY).unwrap();

        let g = Secp256k1::generator();

        let public_key = (g * secret_key).to_affine();

        let r = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(R).unwrap();

        let s = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(S).unwrap();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(MSG_HASH).unwrap();

        let circuit = EcdsaVerifyCircuit::init(public_key, r, s, msg_hash);

        assert_eq!(circuit.instances()[0].len(), circuit.num_instance()[0]);

        let valid_prover = MockProver::run(18, &circuit, circuit.instances()).unwrap();

        valid_prover.assert_satisfied();
    }

    #[test]
    fn test_ecdsa_no_random_invalid_signature() {
        let secret_key = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(SECRET_KEY).unwrap();

        let g = Secp256k1::generator();

        let public_key = (g * secret_key).to_affine();

        let r = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(R).unwrap();

        let invalid_s = <Secp256k1 as CurveAffine>::ScalarExt::from_repr([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(MSG_HASH).unwrap();

        let circuit = EcdsaVerifyCircuit::init(public_key, r, invalid_s, msg_hash);

        let invalid_prover = MockProver::run(18, &circuit, circuit.instances()).unwrap();

        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_ecdsa_no_random_invalid_pub_input() {
        let secret_key = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(SECRET_KEY).unwrap();

        let g = Secp256k1::generator();

        let public_key = (g * secret_key).to_affine();

        let r = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(R).unwrap();

        let s = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(S).unwrap();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(MSG_HASH).unwrap();

        // let's use the generator g as public key added to the instance column. It should fail because this is not the public key used to sign the message
        let limbs_x = decompose(g.x, 4, 68)
            .iter()
            .map(|x| big_to_fe(fe_to_big(*x)))
            .collect::<Vec<Fp>>();

        let limbs_y = decompose(g.y, 4, 68)
            .iter()
            .map(|y| big_to_fe(fe_to_big(*y)))
            .collect::<Vec<Fp>>();

        let mut invalid_pub_input = vec![];
        invalid_pub_input.extend(limbs_x);
        invalid_pub_input.extend(limbs_y);

        let instance = vec![invalid_pub_input];

        let circuit = EcdsaVerifyCircuit::init(public_key, r, s, msg_hash);

        let invalid_prover = MockProver::run(18, &circuit, instance).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 10
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 11
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 12
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 13
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 15
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 16
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 17
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 4).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "ecdsa verify region").into(),
                        offset: 18
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 3 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 4 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 5 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 6 }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 7 }
                },
            ])
        );
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_merkle_sum_tree() {
        use plotters::prelude::*;

        let circuit = MstInclusionCircuit::<LEVELS, MST_WIDTH, N_ASSETS>::init(
            "src/merkle_sum_tree/csv/entry_16.csv",
            0,
        );

        let root = BitMapBackend::new("prints/merkle-sum-tree-layout.png", (2048, 16384))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Layout", ("sans-serif", 25))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(9, &circuit, &root)
            .unwrap();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_ecdsa() {
        use plotters::prelude::*;

        let secret_key = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(SECRET_KEY).unwrap();

        let g = Secp256k1::generator();

        let public_key = (g * secret_key).to_affine();

        let r = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(R).unwrap();

        let s = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(S).unwrap();

        let msg_hash = <Secp256k1 as CurveAffine>::ScalarExt::from_repr(MSG_HASH).unwrap();

        let limbs_x = decompose(public_key.x, 4, 68)
            .iter()
            .map(|x| big_to_fe(fe_to_big(*x)))
            .collect::<Vec<Fp>>();

        let limbs_y = decompose(public_key.y, 4, 68)
            .iter()
            .map(|y| big_to_fe(fe_to_big(*y)))
            .collect::<Vec<Fp>>();

        // merge limbs_x and limbs_y into a single vector
        let mut pub_input = vec![];
        pub_input.extend(limbs_x);
        pub_input.extend(limbs_y);

        let circuit = EcdsaVerifyCircuit::init(public_key, r, s, msg_hash);

        let root = BitMapBackend::new("prints/ecdsa-layout.png", (2048, 16384)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("ECDSA Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(18, &circuit, &root)
            .unwrap();
    }
}
