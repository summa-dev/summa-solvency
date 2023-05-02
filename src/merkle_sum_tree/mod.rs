mod entry;
mod merkle_sum_tree_lib;
mod utils;
use halo2_proofs::halo2curves::bn256::{Fr as Fp};

#[derive(Default, Clone, Debug)]
pub struct MerkleProof {
    pub root_hash: Fp,
    pub entry: Entry,
    pub sibling_hashes: Vec<Fp>,
    pub sibling_sums: Vec<Fp>,
    pub path_indices: Vec<Fp>,
}

#[derive(Default, Clone, Debug)]
pub struct Node {
    pub hash: Fp,
    pub balance: Fp,
}

pub use entry::Entry;
pub use merkle_sum_tree_lib::MerkleSumTree;
pub use utils::big_intify_username;

#[cfg(test)]
mod tests {

    use super::{Entry, MerkleSumTree};

    #[test]
    fn init_mst() {
        // create new merkle tree
        let merkle_tree = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16.csv").unwrap();

        // get root
        let root = merkle_tree.root();

        // expect root hash to be different than 0
        assert!(root.hash != 0.into());
        assert!(root.balance == 556862.into());
        assert!(*merkle_tree.depth() == 4_usize);

        // get proof
        let proof = merkle_tree.generate_proof(0).unwrap();

        // verify proof
        assert!(merkle_tree.verify_proof(&proof));

        // Should generate different root hashes when changing the entry order
        let merkle_tree_2 = MerkleSumTree::new("src/merkle_sum_tree/csv/entry_16_switched_order.csv").unwrap();
        assert_ne!(root.hash, merkle_tree_2.root().hash);

        // the balance should be the same
        assert_eq!(root.balance, merkle_tree_2.root().balance);

        // should retrun the index of an entry that exist in the tree
        assert_eq!(merkle_tree.index_of("AtwIxZHo", 35479), Some(15));

        // shouldn't retrun the index of an entry that doesn't exist in the tree
        assert_eq!(merkle_tree.index_of("AtwHHHHo", 35478), None);

        // should create valid proof for each entry in the tree and verify it
        for i in 0..15 {
            let proof = merkle_tree.generate_proof(i).unwrap();
            assert!(merkle_tree.verify_proof(&proof));
        }

        // shouldn't create a proof for an entry that doesn't exist in the tree
        assert!(merkle_tree.generate_proof(16).is_err());

        // shouldn't verify a proof with a wrong entry
        let mut proof_invalid_1 = proof.clone();
        proof_invalid_1.entry = Entry::new("AtwIxZHo".to_string(), 35479).unwrap();
        assert!(!merkle_tree.verify_proof(&proof_invalid_1));

        // shouldn't verify a proof with a wrong root hash
        let mut proof_invalid_2 = proof.clone();
        proof_invalid_2.root_hash = 0.into();
        assert!(!merkle_tree.verify_proof(&proof_invalid_2));

        // shouldn't verify a proof with a wrong computed balance
        let mut proof_invalid_3 = proof.clone();
        proof_invalid_3.sibling_sums[0] = 0.into();
    }
}
