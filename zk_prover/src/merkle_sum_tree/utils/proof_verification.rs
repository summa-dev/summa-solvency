use crate::merkle_sum_tree::utils::big_uint_to_fp;
use crate::merkle_sum_tree::{MerkleProof, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn verify_proof<const N_ASSETS: usize>(proof: &MerkleProof<N_ASSETS>) -> bool
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    let mut node = proof.entry.compute_leaf();
    let mut balances = proof
        .entry
        .balances()
        .iter()
        .map(big_uint_to_fp)
        .collect::<Vec<Fp>>();

    for i in 0..proof.sibling_hashes.len() {
        let sibling_node = Node {
            hash: proof.sibling_hashes[i],
            balances: proof.sibling_sums[i],
        };

        if proof.path_indices[i] == 0.into() {
            node = Node::middle(&node, &sibling_node);
        } else {
            node = Node::middle(&sibling_node, &node);
        }

        for (balance, sibling_balance) in balances.iter_mut().zip(sibling_node.balances.iter()) {
            *balance += sibling_balance;
        }
    }

    proof.root_hash == node.hash && balances == node.balances
}
