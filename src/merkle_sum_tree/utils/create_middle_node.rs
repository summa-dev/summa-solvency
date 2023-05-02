use super::hash::poseidon;
use crate::merkle_sum_tree::Node;

pub fn create_middle_node(child_l: &Node, child_r: &Node) -> Node {
    Node {
        hash: poseidon(child_l.hash, child_l.balance, child_r.hash, child_r.balance),
        balance: child_l.balance + child_r.balance,
    }
}
