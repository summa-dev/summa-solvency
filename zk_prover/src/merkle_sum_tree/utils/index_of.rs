use crate::merkle_sum_tree::{Entry, Node};
use num_bigint::BigInt;

pub fn index_of<const N_ASSETS: usize>(
    username: &str,
    balances: [BigInt; N_ASSETS],
    nodes: &[Vec<Node<N_ASSETS>>],
) -> Option<usize> {
    let entry: Entry<N_ASSETS> = Entry::new(username.to_string(), balances).unwrap();
    let leaf = entry.compute_leaf();
    let leaf_hash = leaf.hash;

    nodes[0].iter().position(|node| node.hash == leaf_hash)
}
