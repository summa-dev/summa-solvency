#[cfg(test)]
mod test {


    use crate::circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{full_prover, full_verifier, generate_setup_artifacts, get_verification_cost},
    };
    use crate::merkle_sum_tree::MerkleSumTree;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };
    use snark_verifier_sdk::{
        evm::{evm_verify, gen_evm_proof_shplonk, gen_evm_verifier_shplonk},
        CircuitExt,
    };

    const N_ASSETS: usize = 2;
    const LEVELS: usize = 4;
    const K: u32 = 11;

    #[test]
    fn test_valid_merkle_sum_tree() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        for user_index in 0..16 {
            let circuit =
                MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree.clone(), user_index);

            let valid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

            assert_eq!(circuit.instances()[0].len(), circuit.num_instance()[0]);

            valid_prover.assert_satisfied();
        }
    }

    #[test]
    fn test_valid_merkle_sum_tree_with_full_prover() {
        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init_empty();

        // Generate a universal trusted setup for testing purposes.
        //
        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the height of the Merkle tree.
        let (params, pk, vk) = generate_setup_artifacts(K, None, circuit).unwrap();

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit.clone(), circuit.instances());

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, circuit.instances()));
    }

    #[test]
    fn test_valid_solvency_with_full_prover() {
        let circuit = SolvencyCircuit::<N_ASSETS>::init_empty();

        // The verification key (vk) and the proving key (pk) are then generated.
        // An empty circuit is used here to emphasize that the circuit inputs are not relevant when generating the keys.
        // Important: The dimensions of the circuit used to generate the keys must match those of the circuit used to generate the proof.
        // In this case, the dimensions are represented by the height of the Merkle tree.
        let (params, pk, vk) = generate_setup_artifacts(10, None, circuit).unwrap();

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let asset_sums = [Fp::from(556863u64), Fp::from(556863u64)];

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree, asset_sums);

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit.clone(), circuit.instances());

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, circuit.instances()));
    }

    // Passing an invalid root hash in the instance column should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_root_hash() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let mut instances = circuit.instances();
        let invalid_root_hash = Fp::from(1000u64);
        instances[0][1] = invalid_root_hash;

        let invalid_prover = MockProver::run(K, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (94, "permute state").into(),
                        offset: 36
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
        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init_empty();

        // generate a universal trusted setup for testing, along with the verification key (vk) and the proving key (pk).
        let (params, pk, vk) = generate_setup_artifacts(K, None, circuit).unwrap();

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let invalid_root_hash = Fp::from(1000u64);

        let mut instances = circuit.instances();
        instances[0][1] = invalid_root_hash;

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, instances.clone());

        // verify the proof to be false
        assert!(!full_verifier(&params, &vk, proof, instances));
    }

    // Passing an invalid entry balance as input for the witness generation should fail:
    // - the permutation check between the leaf hash and the instance column leaf hash
    // - the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_entry_balance_as_witness() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let mut circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let instances = circuit.instances();

        let invalid_leaf_balances = [1000.to_biguint().unwrap(), 1000.to_biguint().unwrap()];

        // invalidate user entry
        let invalid_entry =
            Entry::new(circuit.entry.username().to_string(), invalid_leaf_balances).unwrap();

        circuit.entry = invalid_entry;

        let invalid_prover = MockProver::run(K, &circuit, instances).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (12, "assign nodes hashes per merkle tree level").into(),
                        offset: 0
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (94, "permute state").into(),
                        offset: 36
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
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let mut instances = circuit.instances();
        let invalid_leaf_hash = Fp::from(1000u64);
        instances[0][0] = invalid_leaf_hash;

        let invalid_prover = MockProver::run(K, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (12, "assign nodes hashes per merkle tree level").into(),
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

    // Passing a non binary index should fail the bool constraint inside "assign nodes hashes per merkle tree level" and "assign nodes balances per asset" region and the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_non_binary_index() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let mut circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let instances = circuit.instances();

        // invalidate path index inside the circuit
        circuit.path_indices[0] = Fp::from(2);

        let invalid_prover = MockProver::run(K, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((6, "bool constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (12, "assign nodes hashes per merkle tree level").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::advice(), 2).into(), 0).into(), "0x2".to_string()),]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((6, "bool constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (13, "assign nodes balances per asset").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::advice(), 2).into(), 0).into(), "0x2".to_string()),]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((6, "bool constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (16, "assign nodes balances per asset").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::advice(), 2).into(), 0).into(), "0x2".to_string()),]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((4, "swap constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (3, "assign nodes hashes per merkle tree level").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (
                            ((Any::advice(), 0).into(), 0).into(),
                            "0xe113acd03b98f0bab0ef6f577245d5d008cbcc19ef2dab3608aa4f37f72a407"
                                .to_string()
                        ),
                        (
                            ((Any::advice(), 0).into(), 1).into(),
                            "0x17ef9d8ee0e2c8470814651413b71009a607a020214f749687384a7b7a7eb67a"
                                .to_string()
                        ),
                        (
                            ((Any::advice(), 1).into(), 0).into(),
                            "0x17ef9d8ee0e2c8470814651413b71009a607a020214f749687384a7b7a7eb67a"
                                .to_string()
                        ),
                        (
                            ((Any::advice(), 1).into(), 1).into(),
                            "0xe113acd03b98f0bab0ef6f577245d5d008cbcc19ef2dab3608aa4f37f72a407"
                                .to_string()
                        ),
                        (((Any::advice(), 2).into(), 0).into(), "0x2".to_string()),
                    ]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((4, "swap constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (4, "assign nodes balances per asset").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::advice(), 0).into(), 0).into(), "0x2e70".to_string()),
                        (((Any::advice(), 0).into(), 1).into(), "0x108ef".to_string()),
                        (((Any::advice(), 1).into(), 0).into(), "0x108ef".to_string()),
                        (((Any::advice(), 1).into(), 1).into(), "0x2e70".to_string()),
                        (((Any::advice(), 2).into(), 0).into(), "0x2".to_string()),
                    ]
                },
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((4, "swap constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (7, "assign nodes balances per asset").into(),
                        offset: 0
                    },
                    cell_values: vec![
                        (((Any::advice(), 0).into(), 0).into(), "0xa0cb".to_string()),
                        (((Any::advice(), 0).into(), 1).into(), "0x48db".to_string()),
                        (((Any::advice(), 1).into(), 0).into(), "0x48db".to_string()),
                        (((Any::advice(), 1).into(), 1).into(), "0xa0cb".to_string()),
                        (((Any::advice(), 2).into(), 0).into(), "0x2".to_string()),
                    ]
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (94, "permute state").into(),
                        offset: 36
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
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let mut circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let instances = circuit.instances();

        // swap indices
        circuit.path_indices[0] = Fp::from(1);

        let invalid_prover = MockProver::run(K, &circuit, instances).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (94, "permute state").into(),
                        offset: 36
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 1 }
                },
            ])
        );
    }

    // Passing asset_sums that are less than the liabilities sum should not fail the solvency circuit
    #[test]
    fn test_valid_liabilities_less_than_assets() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // Make the first asset sum more than liabilities sum (556862)
        let asset_sums = [Fp::from(556863u64), Fp::from(556863u64)];

        let circuit = SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree, asset_sums);

        let valid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

        valid_prover.assert_satisfied();
    }

    #[test]
    fn test_solvency_on_chain_verifier() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let asset_sums = [Fp::from(556863u64), Fp::from(556863u64)];

        let circuit = SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree, asset_sums);

        // generate a universal trusted setup for testing, along with the verification key (vk) and the proving key (pk).
        let (params, pk, _) = generate_setup_artifacts(10, None, circuit.clone()).unwrap();

        get_verification_cost(&params, &pk, circuit.clone());

        let num_instances = circuit.num_instance();
        let instances = circuit.instances();

        let proof_calldata = gen_evm_proof_shplonk(&params, &pk, circuit, instances.clone());

        let deployment_code = gen_evm_verifier_shplonk::<SolvencyCircuit<N_ASSETS>>(
            &params,
            pk.get_vk(),
            num_instances,
            None,
        );

        let gas_cost = evm_verify(deployment_code, instances, proof_calldata);

        assert!(
            (350000..=450000).contains(&gas_cost),
            "gas_cost is not within the expected range"
        );
    }

    // Passing assets sum that is less than the liabilities sum should fail the solvency circuit
    #[test]
    fn test_invalid_assets_less_than_liabilities() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // Make the first asset sum less than liabilities sum (556862)
        let less_than_asset_sums_1st = [Fp::from(556861u64), Fp::from(556863u64)];

        let circuit =
            SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree.clone(), less_than_asset_sums_1st);

        let invalid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

        assert_eq!(
                invalid_prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((7, "is_lt is 1").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (21, "enforce input cell to be less than value in instance column at row `index`").into(),
                        offset: 1
                    },
                    cell_values: vec![
                        // The zero means that is not less than
                        (((Any::advice(), 1).into(), 0).into(), "0".to_string())
                    ]
                }])
            );

        // Make the second asset sum less than liabilities sum (556862)
        let less_than_asset_sums_2nd = [Fp::from(556863u64), Fp::from(556861u64)];

        let circuit =
            SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree.clone(), less_than_asset_sums_2nd);

        let invalid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

        assert_eq!(
                invalid_prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((7, "is_lt is 1").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (22, "enforce input cell to be less than value in instance column at row `index`").into(),
                        offset: 1
                    },
                    cell_values: vec![
                        // The zero means that is not less than
                        (((Any::advice(), 1).into(), 0).into(), "0".to_string())
                    ]
                }])
            );

        // Make both the balances less than liabilities sum (556862)
        let less_than_asset_sums_both = [Fp::from(556861u64), Fp::from(556861u64)];

        let circuit = SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree, less_than_asset_sums_both);

        let invalid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

        assert_eq!(
                invalid_prover.verify(),
                Err(vec![
                    VerifyFailure::ConstraintNotSatisfied {
                        constraint: ((7, "is_lt is 1").into(), 0, "").into(),
                        location: FailureLocation::InRegion {
                            region: (21, "enforce input cell to be less than value in instance column at row `index`").into(),
                            offset: 1
                        },
                        cell_values: vec![
                            // The zero means that is not less than
                            (((Any::advice(), 1).into(), 0).into(), "0".to_string())
                        ]
                    },
                    VerifyFailure::ConstraintNotSatisfied {
                        constraint: ((7, "is_lt is 1").into(), 0, "").into(),
                        location: FailureLocation::InRegion {
                            region: (22, "enforce input cell to be less than value in instance column at row `index`").into(),
                            offset: 1
                        },
                        cell_values: vec![
                            // The zero means that is not less than
                            (((Any::advice(), 1).into(), 0).into(), "0".to_string())
                        ]
                    }
                ])
            );
    }

    // Manipulating the liabilities to make it less than the assets sum should fail the solvency circuit because the root hash will not match
    #[test]
    fn test_invalid_manipulated_liabilties() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // For the second asset, the asset_sums is less than the liabilities sum (556862) namely the CEX is not solvent!
        let less_than_asset_sums_2nd = [Fp::from(556863u64), Fp::from(556861u64)];

        let mut circuit =
            SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree, less_than_asset_sums_2nd);

        // But actually, the CEX tries to manipulate the liabilities sum for the second asset to make it less than the assets sum and result solvent
        circuit.left_node_balances[1] = Fp::from(1u64);

        // This should pass the less the less than constraint but generate a root hash that does not match the one passed in the instance
        let invalid_prover = MockProver::run(K, &circuit, circuit.instances()).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (19, "permute state").into(),
                        offset: 36
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 0 }
                },
            ])
        );
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_mst_inclusion() {
        use plotters::prelude::*;

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(merkle_sum_tree, 0);

        let root = BitMapBackend::new("prints/mst-inclusion-layout.png", (2048, 32768))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Inclusion Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(K, &circuit, &root)
            .unwrap();
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_solvency_circuit() {
        use plotters::prelude::*;

        let asset_sums = [Fp::from(556863u64), Fp::from(556863u64)];

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let circuit = SolvencyCircuit::<N_ASSETS>::init(merkle_sum_tree, asset_sums);

        let root =
            BitMapBackend::new("prints/solvency-layout.png", (2048, 32768)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Solvency Layout", ("sans-serif", 60)).unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(K, &circuit, &root)
            .unwrap();
    }
}
