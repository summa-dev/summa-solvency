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

    print!("Building merkle tree with {} leaves and {} depth", n, depth);

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

    let pf_time = start_timer!(|| "compute leaves");

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

    end_timer!(pf_time);

    for level in 1..=depth {
        let nodes_in_level = (n + (1 << level) - 1) / (1 << level);

        // compute parallelization until {parallelization_threshold} level
        // if parallelization_threshold is set to depth, then no parallelization
        // if parallelization_threshold is set to 0, then all levels are parallelized (until level 0)
        // if depth is smaller than 5, disable parallelization
        // otherwise, only parallelize the initial 5 levels
        let parallelization_threshold = if depth < 5 { depth } else { depth - 5 };

        if level > depth - parallelization_threshold {
            let pf_time = start_timer!(|| "compute middle level sequentially");
            print!("{} ", depth - level);

            for i in 0..nodes_in_level {
                tree[level][i] =
                    create_middle_node(&tree[level - 1][2 * i], &tree[level - 1][2 * i + 1]);
            }

            end_timer!(pf_time);
            continue;
        } else {
            let mut handles = vec![];
            let chunk_size = (nodes_in_level + num_cpus::get() - 1) / num_cpus::get();
            let pf_time = start_timer!(|| "compute middle level in parallel");
            print!("{} ", depth - level);

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

            end_timer!(pf_time);
            continue;
        }
    }

    let root = tree[depth][0].clone();
    *nodes = tree;
    Ok(root)
}
