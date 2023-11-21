#[cfg(test)]
mod test {

    use crate::merkle_sum_tree::utils::{big_uint_to_fp, poseidon_entry, poseidon_node};
    use crate::merkle_sum_tree::{Entry, MerkleSumTree, Tree};
    use num_bigint::{BigUint, ToBigUint};
    use rand::Rng as _;

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
        proof_invalid_2.root.hash = 0.into();
        assert!(!merkle_tree.verify_proof(&proof_invalid_2));
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
    fn get_middle_node_hash_preimage() {
        let merkle_tree =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        let depth = *merkle_tree.depth();

        // The tree has 16 leaves, so the levels are 0, 1, 2, 3, 4. Where level 0 is the leaves and level 4 is the root
        // Fetch a random level from 1 to depth
        let mut rng = rand::thread_rng();
        let level = rng.gen_range(1..depth);

        // Fetch a random index inside the level. For example level 1 has 8 nodes, so the index can be 0, 1, 2, 3, 4, 5, 6, 7
        let index = rng.gen_range(0..merkle_tree.nodes()[level].len());

        // Fetch middle node with index from level
        let middle_node = merkle_tree.nodes()[level][index].clone();

        // Fetch the hash preimage of the middle node
        let hash_preimage = merkle_tree
            .get_middle_node_hash_preimage(level, index)
            .unwrap();

        let mut balances = vec![];

        // loop from 0 to N_ASSETS and push the value in the hash preimage to the balances vector
        for i in 0..N_ASSETS {
            balances.push(hash_preimage[i]);
        }

        // Perform the poseidon hash on the hash preimage
        let hash = poseidon_node::<N_ASSETS>(
            balances.try_into().unwrap(),
            hash_preimage[2],
            hash_preimage[3],
        );

        // The hash of the middle node should match the hash computed from the hash preimage
        assert_eq!(middle_node.hash, hash);
    }

    #[test]
    fn get_leaf_node_hash_preimage() {
        let merkle_tree =
            MerkleSumTree::<N_ASSETS, N_BYTES>::new("src/merkle_sum_tree/csv/entry_16.csv")
                .unwrap();

        // Generate a random number between 0 and 15
        let mut rng = rand::thread_rng();
        let index = rng.gen_range(0..16);

        // Fetch leaf with index
        let leaf = merkle_tree.leaves()[index].clone();

        // Fetch the hash preimage of the leaf
        let hash_preimage = merkle_tree.get_leaf_node_hash_preimage(index).unwrap();

        // Extract the balances from the hash preimage
        let mut balances = vec![];

        // loop from 1 to N_ASSETS + 1 and push the value in the hash preimage to the balances vector
        for i in 1..N_ASSETS + 1 {
            balances.push(hash_preimage[i]);
        }

        let username = hash_preimage[0];

        // Perform the poseidon hash on the hash preimage
        let hash = poseidon_entry::<N_ASSETS>(username, balances.try_into().unwrap());

        // The hash of the middle node should match the hash computed from the hash preimage
        assert_eq!(leaf.hash, hash);
    }
}
