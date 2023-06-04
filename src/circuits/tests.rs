#[cfg(test)]
mod test {

    use crate::circuits::utils::{
        full_prover, full_verifier, generate_setup_params, instantiate_circuit,
        instantiate_empty_circuit,
    };
    use crate::merkle_sum_tree::{MerkleProof, MerkleSumTree, MST_WIDTH, N_ASSETS};
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::{keygen_pk, keygen_vk, Any},
    };

    #[test]
    fn test_valid_merkle_sum_tree() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // loop over each index and generate a proof for each one
        for user_index in 0..16 {
            let mt_proof: MerkleProof<N_ASSETS> =
                merkle_sum_tree.generate_proof(user_index).unwrap();
            // assets_sum are defined as liabilities_sum + 1
            let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

            let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

            let mut public_input = vec![circuit.leaf_hash];
            public_input.extend(&circuit.leaf_balances);
            public_input.push(circuit.root_hash);
            public_input.extend(&circuit.assets_sum);

            let valid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

            valid_prover.assert_satisfied();
        }
    }

    #[test]
    fn test_valid_merkle_sum_tree_2() {
        // Same as above but now the entries contain a balance that is greater than 64 bits
        // liabilities sum is 18446744073710096590

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16_bigints.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();
        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let valid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        valid_prover.assert_satisfied();
    }

    #[test]
    fn test_valid_merkle_sum_tree_with_full_prover() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let levels = 4;

        let circuit = instantiate_empty_circuit::<MST_WIDTH, N_ASSETS>(levels);

        // we generate a universal trusted setup of our own for testing
        let params = generate_setup_params(levels);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        // Note: the dimension of the empty circuit used to generate the keys must be the same as the dimension of the circuit used to generate the proof
        // In this case, the dimension are represented by the heigth of the merkle tree
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();
        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, &public_input);

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, &public_input));
    }

    // Passing an invalid root hash in the instance column should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_root_hash() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();
        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        let invalid_root_hash = Fp::from(1000u64);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(invalid_root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    #[test]
    fn test_invalid_root_hash_with_full_prover() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let levels = 4;

        let circuit = instantiate_empty_circuit::<MST_WIDTH, N_ASSETS>(levels);

        // we generate a universal trusted setup of our own for testing
        let params = generate_setup_params(levels);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();
        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        let invalid_root_hash = Fp::from(1000u64);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(invalid_root_hash);
        public_input.extend(&circuit.assets_sum);

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, &public_input);

        // verify the proof to be false
        assert!(!full_verifier(&params, &vk, proof, &public_input));
    }

    // Passing an invalid leaf hash as input for the witness generation should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_hash_as_witness() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let mut circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        // invalidate leaf hash
        circuit.leaf_hash = Fp::from(1000u64);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Passing an invalid leaf hash in the instance column should fail the permutation check between the (valid) leaf hash added as part of the witness and the instance column leaf hash
    #[test]
    fn test_invalid_leaf_hash_as_instance() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);
        // add invalid leaf hash in the instance column
        let invalid_leaf_hash = Fp::from(1000u64);

        let mut public_input = vec![invalid_leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 3).into(),
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

    // Passing an invalid leaf balance as input for the witness generation should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_balance_as_witness() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let mut circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        let user_balance = [Fp::from(11888u64)];

        // invalid leaf balance
        circuit.leaf_hash = Fp::from(1000u64);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(user_balance);
        public_input.push(circuit.root_hash);
        public_input.extend(assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Passing an invalid leaf balance in the instance column should fail the permutation check between the (valid) leaf balance added as part of the witness and the instance column leaf balance
    #[test]
    fn test_invalid_leaf_balance_as_instance() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        // add invalid leaf balance in the instance column
        let invalid_leaf_balance = [Fp::from(1000u64)];

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(invalid_leaf_balance);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 0).into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
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
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        // assets_sum are defined as liabilities_sum + 1
        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64));

        let mut circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        // invalidate path index inside the circuit
        circuit.path_indices[0] = Fp::from(2);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "bool constraint").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (1, "merkle prove layer").into(),
                        offset: 0
                    },
                    cell_values: vec![(((Any::advice(), 5).into(), 0).into(), "0x2".to_string()),]
                },
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Swapping the indices should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_swapping_index() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64)); // assets_sum are defined as liabilities_sum + 1

        let mut circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);
        // swap indices
        circuit.path_indices[0] = Fp::from(1);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::Instance, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 2 }
                },
                VerifyFailure::Permutation {
                    column: (Any::advice(), 6).into(),
                    location: FailureLocation::InRegion {
                        region: (16, "permute state").into(),
                        offset: 38
                    }
                }
            ])
        );
    }

    // Passing an assets sum that is less than the liabilities sum should fail the lessThan constraint check
    #[test]
    fn test_is_not_less_than() {
        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let less_than_assets_sum = merkle_sum_tree.root().balances.map(|x| x - Fp::from(1u64)); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(less_than_assets_sum, mt_proof);

        let mut public_input = vec![circuit.leaf_hash];
        public_input.extend(&circuit.leaf_balances);
        public_input.push(circuit.root_hash);
        public_input.extend(&circuit.assets_sum);

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (
                        7,
                        "verifies that `check` from current config equal to is_lt from LtChip"
                    )
                        .into(),
                    0,
                    ""
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (18, "enforce sum to be less than total assets").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 2).into(), 0).into(), "1".to_string()),
                    // The zero means that is not less than
                    (((Any::advice(), 12).into(), 0).into(), "0".to_string())
                ]
            }])
        );

        assert!(invalid_prover.verify().is_err());
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_merkle_sum_tree() {
        use plotters::prelude::*;

        let merkle_sum_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let user_index = 0;

        let mt_proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        let assets_sum = merkle_sum_tree.root().balances.map(|x| x + Fp::from(1u64)); // assets_sum are defined as liabilities_sum + 1

        let circuit = instantiate_circuit::<MST_WIDTH, N_ASSETS>(assets_sum, mt_proof);

        let root = BitMapBackend::new("prints/merkle-sum-tree-layout.png", (2048, 16384))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(8, &circuit, &root)
            .unwrap();
    }
}
