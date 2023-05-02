use super::create_middle_node::create_middle_node;
use crate::merkle_sum_tree::{Entry, Node};
use halo2_proofs::halo2curves::bn256::{Fr as Fp};

pub fn build_merkle_tree_from_entries(
    entries: &[Entry],
    depth: usize,
    nodes: &mut Vec<Vec<Node>>,
) -> Result<Node, Box<dyn std::error::Error>> {
    let n = entries.len();
    let mut tree = vec![
        vec![
            Node {
                hash: Fp::from(0),
                balance: Fp::from(0)
            };
            n
        ];
        depth + 1
    ];

    // Compute the leaves
    for (i, entry) in entries.iter().enumerate() {
        tree[0][i] = entry.compute_leaf();
    }

    // Compute the inner nodes
    for level in 1..=depth {
        let nodes_in_level = (n + (1 << level) - 1) / (1 << level);
        for i in 0..nodes_in_level {
            tree[level][i] =
                create_middle_node(&tree[level - 1][2 * i], &tree[level - 1][2 * i + 1]);

            // let left_child = tree[level - 1][2 * i].hash;
            // let right_child = tree[level - 1][2 * i + 1].hash;
            // tree[level][i].hash = poseidon(left_child, right_child);
        }
    }

    let root = tree[depth][0].clone();
    *nodes = tree;
    Ok(root)
}
