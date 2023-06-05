use crate::merkle_sum_tree::utils::create_middle_node::create_middle_node;
use crate::merkle_sum_tree::{Entry, Node};
use ark_std::{end_timer, start_timer};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use std::thread;

pub fn build_merkle_tree_from_entries(
    entries: &[Entry],
    depth: usize,
    nodes: &mut Vec<Vec<Node>>,
) -> Result<Node, Box<dyn std::error::Error>> {
    let n = entries.len();

    let tree_building = start_timer!(|| "build merkle tree");

    let mut tree: Vec<Vec<Node>> = Vec::with_capacity(depth + 1);

    tree.push(vec![
        Node {
            hash: Fp::from(0),
            balance: Fp::from(0)
        };
        n
    ]);

    for _ in 1..=depth {
        let previous_level = tree.last().unwrap();
        let nodes_in_level = (previous_level.len() + 1) / 2;

        tree.push(vec![
            Node {
                hash: Fp::from(0),
                balance: Fp::from(0)
            };
            nodes_in_level
        ]);
    }

    build_leaves_level(entries, &mut tree);

    for level in 1..=depth {
        build_middle_level(level, &mut tree, n)
    }
    end_timer!(tree_building);

    let root = tree[depth][0].clone();
    *nodes = tree;
    Ok(root)
}

fn build_leaves_level(entries: &[Entry], tree: &mut [Vec<Node>]) {
    let leaves_building = start_timer!(|| "compute leaves");
    // Compute the leaves in parallel
    let mut handles = vec![];
    let chunk_size = (entries.len() + num_cpus::get() - 1) / num_cpus::get();
    for chunk in entries.chunks(chunk_size) {
        let chunk = chunk.to_vec();
        handles.push(thread::spawn(move || {
            chunk
                .into_iter()
                .map(|entry| entry.compute_leaf())
                .collect::<Vec<_>>()
        }));
    }

    let mut index = 0;
    for handle in handles {
        let result = handle.join().unwrap();
        for leaf in result {
            tree[0][index] = leaf;
            index += 1;
        }
    }
    end_timer!(leaves_building);
}

fn build_middle_level(level: usize, tree: &mut [Vec<Node>], n: usize) {
    let nodes_in_level = (n + (1 << level) - 1) / (1 << level);

    let mut handles = vec![];
    let chunk_size = (nodes_in_level + num_cpus::get() - 1) / num_cpus::get();
    let middle_level_building = start_timer!(|| "compute middle level in parallel");

    for chunk in tree[level - 1].chunks(chunk_size * 2) {
        let chunk = chunk.to_vec();
        handles.push(thread::spawn(move || {
            chunk
                .chunks(2)
                .map(|pair| create_middle_node(&pair[0], &pair[1]))
                .collect::<Vec<_>>()
        }));
    }

    let mut index = 0;
    for handle in handles {
        let result = handle.join().unwrap();
        for node in result {
            tree[level][index] = node;
            index += 1;
        }
    }

    end_timer!(middle_level_building);
}
