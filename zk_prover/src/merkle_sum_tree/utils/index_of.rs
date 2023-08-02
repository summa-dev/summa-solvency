use crate::merkle_sum_tree::{Entry, Node};
use num_bigint::BigUint;

pub fn index_of<const N_ASSETS: usize>(
    username: &str,
    balances: [BigUint; N_ASSETS],
    nodes: &[Vec<Node<N_ASSETS>>],
) -> Option<usize>
where
    [(); N_ASSETS + 1]: Sized,
{
    let entry: Entry<N_ASSETS> = Entry::new(username.to_string(), balances).unwrap();
    let leaf = entry.compute_leaf();
    let leaf_hash = leaf.hash;

    nodes[0].iter().position(|node| node.hash == leaf_hash)
}
