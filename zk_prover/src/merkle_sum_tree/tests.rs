#[cfg(test)]
mod test {

    use crate::merkle_sum_tree::utils::{big_uint_to_fp, poseidon_node};
    use crate::merkle_sum_tree::{Entry, MerkleSumTree, N_ASSETS};
    use num_bigint::{BigUint, ToBigUint};

    #[test]
    fn test_mst() {
        // create new merkle tree
        let merkle_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // get root
        let root = merkle_tree.root();

        // expect root hash to be different than 0
        assert!(root.hash != 0.into());
        // expect balance to match the sum of all entries
        assert!(root.balances == [556862.into(), 556862.into()]);
        // expect depth to be 4
        assert!(*merkle_tree.depth() == 4_usize);

        // get proof for entry 0
        let proof = merkle_tree.generate_proof(0).unwrap();

        // verify proof
        assert!(merkle_tree.verify_proof(&proof));

        // Should generate different root hashes when changing the entry order
        let merkle_tree_2 =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16_switched_order.csv")
                .unwrap();
        assert_ne!(root.hash, merkle_tree_2.root().hash);

        // the balance total should be the same
        assert_eq!(root.balances, merkle_tree_2.root().balances);

        // should retrun the index of an entry that exist in the tree
        assert_eq!(
            merkle_tree.index_of(
                "AtwIxZHo",
                [35479.to_biguint().unwrap(), 31699.to_biguint().unwrap()]
            ),
            Some(15)
        );

        // shouldn't retrun the index of an entry that doesn't exist in the tree
        assert_eq!(
            merkle_tree.index_of(
                "AtwHHHHo",
                [35478.to_biguint().unwrap(), 35478.to_biguint().unwrap()]
            ),
            None
        );

        // should create valid proof for each entry in the tree and verify it
        for i in 0..15 {
            let proof = merkle_tree.generate_proof(i).unwrap();
            assert!(merkle_tree.verify_proof(&proof));
        }

        // shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(merkle_tree.generate_proof(16).is_err());

        // shouldn't verify a proof with a wrong entry
        let mut proof_invalid_1 = proof.clone();
        proof_invalid_1.entry = Entry::new(
            "AtwIxZHo".to_string(),
            [35479.to_biguint().unwrap(), 35479.to_biguint().unwrap()],
        )
        .unwrap();
        assert!(!merkle_tree.verify_proof(&proof_invalid_1));

        // shouldn't verify a proof with a wrong root hash
        let mut proof_invalid_2 = proof.clone();
        proof_invalid_2.root_hash = 0.into();
        assert!(!merkle_tree.verify_proof(&proof_invalid_2));

        // shouldn't verify a proof with a wrong computed balance
        let mut proof_invalid_3 = proof;
        proof_invalid_3.sibling_sums[0] = [0.into(), 0.into()];
    }

    #[test]
    fn test_mst_overflow() {
        let result =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16_overflow.csv");

        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                "Accumulated balance is not in the expected range, proof generation will fail!"
            );
        }
    }

    #[test]
    fn test_big_int_conversion() {
        let big_int = 3.to_biguint().unwrap();
        let fp = big_uint_to_fp(&big_int);

        assert_eq!(fp, 3.into());

        let big_int_over_64 = (18446744073709551616_i128).to_biguint().unwrap();
        let fp_2 = big_uint_to_fp(&big_int_over_64);

        let big_int_to_bytes = {
            let mut bytes = BigUint::to_bytes_le(&big_int_over_64);
            bytes.resize(32, 0);
            bytes
        };

        assert_eq!(fp_2.to_bytes().to_vec(), big_int_to_bytes);

        let fp_3 = fp_2 - fp;
        assert_eq!(fp_3, 18446744073709551613.into());
    }

    #[test]
    fn test_penultimate_level_data() {
        let merkle_tree =
            MerkleSumTree::<N_ASSETS>::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        let root = merkle_tree.root();

        let (node_left, node_right) = merkle_tree
            .penultimate_level_data()
            .expect("Failed to retrieve penultimate level data");

        // perform hashing using poseidon node
        let expected_root = poseidon_node(
            node_left.hash,
            node_left.balances,
            node_right.hash,
            node_right.balances,
        );

        assert_eq!(root.hash, expected_root);

        assert_eq!(
            root.balances[0],
            node_left.balances[0] + node_right.balances[0]
        );

        assert_eq!(
            root.balances[1],
            node_left.balances[1] + node_right.balances[1]
        );
    }
}
