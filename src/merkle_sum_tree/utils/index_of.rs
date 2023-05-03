use num_bigint::BigInt;
use crate::merkle_sum_tree::{Entry, Node};

pub fn index_of(username: &str, balance: BigInt, nodes: &[Vec<Node>]) -> Option<usize> {
    let entry = Entry::new(username.to_string(), balance).unwrap();
    let leaf = entry.compute_leaf();
    let leaf_hash = leaf.hash;

    nodes[0].iter().position(|node| node.hash == leaf_hash)
}
