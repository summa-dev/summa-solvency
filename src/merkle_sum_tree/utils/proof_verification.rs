// proof_verification.rs

use super::create_middle_node::create_middle_node;
use crate::merkle_sum_tree::{MerkleProof, Node};
use halo2_proofs::halo2curves::bn256::{Fr as Fp};

pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut node = proof.entry.compute_leaf();
    let mut balance = Fp::from(proof.entry.balance());

    for i in 0..proof.sibling_hashes.len() {
        let sibling_node = Node {
            hash: proof.sibling_hashes[i],
            balance: proof.sibling_sums[i],
        };

        if proof.path_indices[i] == 0.into() {
            node = create_middle_node(&node, &sibling_node);
        } else {
            node = create_middle_node(&sibling_node, &node);
        }

        balance += sibling_node.balance;
    }

    proof.root_hash == node.hash && balance == node.balance
}
