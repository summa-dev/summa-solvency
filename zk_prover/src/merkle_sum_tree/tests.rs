#[cfg(test)]
mod test {

    use crate::merkle_sum_tree::utils::{big_uint_to_fp, poseidon_node};
    use crate::merkle_sum_tree::{AggregationMerkleSumTree, Entry, MerkleSumTree};
    use num_bigint::{BigUint, ToBigUint};

    const N_ASSETS: usize = 2;
    const N_BYTES: usize = 8;

    #[test]
    fn test_mst() {
        // create new merkle tree
        let merkle_tree =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

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
        let merkle_tree_2 = MerkleSumTree::<N_ASSETS, N_BYTES>::new(
            "src/merkle_sum_tree/csv/entry_16_switched_order.csv",
        )
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

        // shouldn't verify a proof with a wrong leaf
        let invalid_entry = Entry::new(
            "AtwIxZHo".to_string(),
            [35479.to_biguint().unwrap(), 35479.to_biguint().unwrap()],
        )
        .unwrap();
        let invalid_leaf = invalid_entry.compute_leaf();
        let mut proof_invalid_1 = proof.clone();
        proof_invalid_1.leaf = invalid_leaf;
        assert!(!merkle_tree.verify_proof(&proof_invalid_1));

        // shouldn't verify a proof with a wrong root hash
        let mut proof_invalid_2 = proof.clone();
        proof_invalid_2.root_hash = 0.into();
        assert!(!merkle_tree.verify_proof(&proof_invalid_2));

        // shouldn't verify a proof with a wrong computed balance
        let mut proof_invalid_3 = proof;
        proof_invalid_3.sibling_sums[0] = [0.into(), 0.into()];
        assert!(!merkle_tree.verify_proof(&proof_invalid_3));
    }

    #[test]
    fn test_update_mst_leaf() {
        let merkle_tree_1 =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let root_hash_1 = merkle_tree_1.root().hash;

        //Create the second tree with the 7th entry different from the the first tree
        let mut merkle_tree_2 = MerkleSumTree::<N_ASSETS, N_BYTES>::new(
            "src/merkle_sum_tree/csv/entry_16_modified.csv",
        )
        .unwrap();

        let root_hash_2 = merkle_tree_2.root().hash;
        assert!(root_hash_1 != root_hash_2);

        //Update the 7th leaf of the second tree so all the entries now match the first tree
        let new_root = merkle_tree_2
            .update_leaf(
                "RkLzkDun",
                &[2087.to_biguint().unwrap(), 79731.to_biguint().unwrap()],
            )
            .unwrap();
        //The roots should match
        assert!(root_hash_1 == new_root.hash);
    }

    #[test]
    fn test_update_invalid_mst_leaf() {
        let mut merkle_tree =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new_sorted("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let new_root = merkle_tree.update_leaf(
            "non_existing_user", //This username is not present in the tree
            &[11888.to_biguint().unwrap(), 41163.to_biguint().unwrap()],
        );

        if let Err(e) = new_root {
            assert_eq!(e.to_string(), "Username not found");
        }
    }

    #[test]
    fn test_sorted_mst() {
        let merkle_tree =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let old_root_balances = merkle_tree.root().balances;
        let old_root_hash = merkle_tree.root().hash;

        let sorted_merkle_tree =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new_sorted("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let new_root_balances = sorted_merkle_tree.root().balances;
        let new_root_hash = sorted_merkle_tree.root().hash;

        // The index of an entry should not be the same for sorted and unsorted MST
        assert_ne!(
            merkle_tree
                .index_of(
                    "AtwIxZHo",
                    [35479.to_biguint().unwrap(), 31699.to_biguint().unwrap()]
                )
                .unwrap(),
            sorted_merkle_tree.index_of_username("AtwIxZHo").unwrap()
        );

        // The root balances should be the same for sorted and unsorted MST
        assert!(old_root_balances == new_root_balances);
        // The root hash should not be the same for sorted and unsorted MST
        assert!(old_root_hash != new_root_hash);
    }

    // Passing a csv file with a single entry that has a balance that is not in the expected range will fail
    #[test]
    fn test_mst_overflow_1() {
        let result = MerkleSumTree::<N_ASSETS, N_BYTES>::new(
            "src/merkle_sum_tree/csv/entry_16_overflow.csv",
        );

        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                "Accumulated balance is not in the expected range, proof generation will fail!"
            );
        }
    }

    #[test]
    // Passing a csv file in which the entries have a balance in the range, but while summing it generates a ndoe in which the balance is not in the expected range will fail
    fn test_mst_overflow_2() {
        let result = MerkleSumTree::<N_ASSETS, N_BYTES>::new(
            "src/merkle_sum_tree/csv/entry_16_overflow_2.csv",
        );

        if let Err(e) = result {
            assert_eq!(
                e.to_string(),
                "Accumulated balance is not in the expected range, proof generation will fail!"
            );
        }
    }

    // Passing a csv file with a single entry that has a balance that is the maximum that can fit in the expected range will not fail
    #[test]
    fn test_mst_no_overflow() {
        let result = MerkleSumTree::<N_ASSETS, N_BYTES>::new(
            "src/merkle_sum_tree/csv/entry_16_no_overflow.csv",
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_big_uint_conversion() {
        let big_uint = 3.to_biguint().unwrap();
        let fp = big_uint_to_fp(&big_uint);

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
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

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

    #[test]
    fn test_aggregation_mst() {
        // create new mini merkle sum tree
        let merkle_sum_tree_1 =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let merkle_sum_tree_2 =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let aggregation_mst = AggregationMerkleSumTree::<N_ASSETS, N_BYTES>::new(vec![
            merkle_sum_tree_1,
            merkle_sum_tree_2.clone(),
        ])
        .unwrap();

        // get root
        let root = aggregation_mst.root();

        // expect root hash to be different than 0
        assert!(root.hash != 0.into());
        // expect balance to match the sum of all entries
        assert!(root.balances == [(556862 * 2).into(), (556862 * 2).into()]);

        // get proof for entry 0
        let proof = aggregation_mst.generate_proof(0, 0).unwrap();

        // verify proof
        assert!(aggregation_mst.verify_proof(&proof));

        // Should generate different root hashes when changing the entry order
        let merkle_sum_tree_3 = MerkleSumTree::<N_ASSETS, N_BYTES>::new(
            "src/merkle_sum_tree/csv/entry_16_switched_order.csv",
        )
        .unwrap();

        let aggregation_mst_2 = AggregationMerkleSumTree::<N_ASSETS, N_BYTES>::new(vec![
            merkle_sum_tree_3,
            merkle_sum_tree_2,
        ])
        .unwrap();

        assert_ne!(root.hash, aggregation_mst_2.root().hash);

        // the balance total should be the same
        assert_eq!(root.balances, aggregation_mst_2.root().balances);

        // should retrun the index of an entry that exist in the tree
        assert_eq!(
            aggregation_mst.mini_tree(0).index_of(
                "AtwIxZHo",
                [35479.to_biguint().unwrap(), 31699.to_biguint().unwrap()]
            ),
            Some(15)
        );

        // shouldn't retrun the index of an entry that doesn't exist in the tree
        assert_eq!(
            aggregation_mst.mini_tree(0).index_of(
                "AtwHHHHo",
                [35478.to_biguint().unwrap(), 35478.to_biguint().unwrap()]
            ),
            None
        );

        // should create valid proof for each entry in the 2 mini-trees and verify it
        for i in 0..15 {
            let proof_1 = aggregation_mst.generate_proof(i, 0).unwrap();
            let proof_2 = aggregation_mst.generate_proof(i, 1).unwrap();
            assert!(aggregation_mst.verify_proof(&proof_1));
            assert!(aggregation_mst.verify_proof(&proof_2));
        }

        // shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(aggregation_mst.generate_proof(16, 0).is_err());

        // shouldn't verify a proof with a wrong root hash
        let mut proof_invalid_1 = proof.clone();
        proof_invalid_1.root_hash = 0.into();
        assert!(!aggregation_mst.verify_proof(&proof_invalid_1));

        // shouldn't verify a proof with a wrong computed balance
        let mut proof_invalid_2 = proof;
        proof_invalid_2.sibling_sums[0] = [0.into(), 0.into()];
        assert!(!aggregation_mst.verify_proof(&proof_invalid_2))
    }
}
