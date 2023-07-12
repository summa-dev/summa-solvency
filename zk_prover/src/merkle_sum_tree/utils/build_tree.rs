use crate::merkle_sum_tree::utils::create_middle_node::create_middle_node;
use crate::merkle_sum_tree::{Entry, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use std::thread;

pub fn build_merkle_tree_from_entries<const N_ASSETS: usize>(
    entries: &[Entry<N_ASSETS>],
    depth: usize,
    nodes: &mut Vec<Vec<Node<N_ASSETS>>>,
) -> Result<Node<N_ASSETS>, Box<dyn std::error::Error>>
where
    [(); N_ASSETS + 1]: Sized,
    [(); 2 * (1 + N_ASSETS)]: Sized,
{
    let n = entries.len();

    let mut tree: Vec<Vec<Node<N_ASSETS>>> = Vec::with_capacity(depth + 1);

    tree.push(vec![
        Node {
            hash: Fp::from(0),
            balances: [Fp::from(0); N_ASSETS]
        };
        n
    ]);

    for _ in 1..=depth {
        let previous_level = tree.last().unwrap();
        let nodes_in_level = (previous_level.len() + 1) / 2;

        tree.push(vec![
            Node {
                hash: Fp::from(0),
                balances: [Fp::from(0); N_ASSETS]
            };
            nodes_in_level
        ]);
    }

    build_leaves_level(entries, &mut tree);

    for level in 1..=depth {
        build_middle_level(level, &mut tree, n)
    }

    let root = tree[depth][0].clone();
    *nodes = tree;
    Ok(root)
}

fn build_leaves_level<const N_ASSETS: usize>(
    entries: &[Entry<N_ASSETS>],
    tree: &mut [Vec<Node<N_ASSETS>>],
) where
    [(); N_ASSETS + 1]: Sized,
{
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
}

fn build_middle_level<const N_ASSETS: usize>(
    level: usize,
    tree: &mut [Vec<Node<N_ASSETS>>],
    n: usize,
) where
    [(); 2 * (1 + N_ASSETS)]: Sized,
{
    let nodes_in_level = (n + (1 << level) - 1) / (1 << level);

    let mut handles = vec![];
    let chunk_size = (nodes_in_level + num_cpus::get() - 1) / num_cpus::get();

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
}
