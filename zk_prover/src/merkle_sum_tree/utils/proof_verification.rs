use crate::merkle_sum_tree::{MerkleProof, Node};

pub fn verify_proof<const N_ASSETS: usize, const N_BYTES: usize>(
    proof: &MerkleProof<N_ASSETS, N_BYTES>,
) -> bool
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    let mut node = proof.leaf.clone();

    let mut balances = proof.leaf.balances;

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
