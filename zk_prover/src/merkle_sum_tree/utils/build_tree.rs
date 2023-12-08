use crate::merkle_sum_tree::{Entry, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use rayon::prelude::*;

pub fn build_merkle_tree_from_leaves<const N_CURRENCIES: usize>(
    leaves: &[Node<N_CURRENCIES>],
    depth: usize,
    nodes: &mut Vec<Vec<Node<N_CURRENCIES>>>,
) -> Result<Node<N_CURRENCIES>, Box<dyn std::error::Error>>
where
    [usize; N_CURRENCIES + 1]: Sized,
    [usize; N_CURRENCIES + 2]: Sized,
{
    let n = leaves.len();

    let mut tree: Vec<Vec<Node<N_CURRENCIES>>> = Vec::with_capacity(depth + 1);

    tree.push(vec![
        Node {
            hash: Fp::from(0),
            balances: [Fp::from(0); N_CURRENCIES]
        };
        n
    ]);

    for _ in 1..=depth {
        let previous_level = tree.last().unwrap();
        let nodes_in_level = (previous_level.len() + 1) / 2;

        tree.push(vec![
            Node {
                hash: Fp::from(0),
                balances: [Fp::from(0); N_CURRENCIES]
            };
            nodes_in_level
        ]);
    }

    for (index, leaf) in leaves.iter().enumerate() {
        tree[0][index] = leaf.clone();
    }

    for level in 1..=depth {
        build_middle_level(level, &mut tree)
    }

    let root = tree[depth][0].clone();
    *nodes = tree;
    Ok(root)
}

pub fn build_leaves_from_entries<const N_CURRENCIES: usize>(
    entries: &[Entry<N_CURRENCIES>],
) -> Vec<Node<N_CURRENCIES>>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    // Precompute the zero leaf (this will only be used if we encounter a zero entry)
    let zero_leaf = Entry::<N_CURRENCIES>::zero_entry().compute_leaf();

    let leaves = entries
        .par_iter()
        .map(|entry| {
            // If the entry is the zero entry then we return the precomputed zero leaf
            // Otherwise, we compute the leaf as usual
            if entry == &Entry::<N_CURRENCIES>::zero_entry() {
                zero_leaf.clone()
            } else {
                entry.compute_leaf()
            }
        })
        .collect::<Vec<_>>();

    leaves
}

fn build_middle_level<const N_CURRENCIES: usize>(level: usize, tree: &mut [Vec<Node<N_CURRENCIES>>])
where
    [usize; N_CURRENCIES + 2]: Sized,
{
    let results: Vec<Node<N_CURRENCIES>> = (0..tree[level - 1].len())
        .into_par_iter()
        .step_by(2)
        .map(|index| {
            let mut hash_preimage = [Fp::zero(); N_CURRENCIES + 2];

            for (i, balance) in hash_preimage.iter_mut().enumerate().take(N_CURRENCIES) {
                *balance =
                    tree[level - 1][index].balances[i] + tree[level - 1][index + 1].balances[i];
            }

            hash_preimage[N_CURRENCIES] = tree[level - 1][index].hash;
            hash_preimage[N_CURRENCIES + 1] = tree[level - 1][index + 1].hash;
            Node::middle_node_from_preimage(&hash_preimage)
        })
        .collect();

    for (index, new_node) in results.into_iter().enumerate() {
        tree[level][index] = new_node;
    }
}
