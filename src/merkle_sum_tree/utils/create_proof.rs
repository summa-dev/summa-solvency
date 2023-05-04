use crate::merkle_sum_tree::{Entry, MerkleProof, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn create_proof(
    index: usize,
    entries: &[Entry],
    depth: usize,
    nodes: &[Vec<Node>],
    root: &Node,
) -> Result<MerkleProof, &'static str> {
    if index >= nodes[0].len() {
        return Err("The leaf does not exist in this tree");
    }

    let mut sibling_hashes = vec![Fp::from(0); depth];
    let mut sibling_sums = vec![Fp::from(0); depth];
    let mut path_indices = vec![Fp::from(0); depth];
    let mut current_index = index;

    for level in 0..depth {
        let position = current_index % 2;
        let level_start_index = current_index - position;
        let level_end_index = level_start_index + 2;

        path_indices[level] = Fp::from(position as u64);

        for i in level_start_index..level_end_index {
            if i != current_index {
                sibling_hashes[level] = nodes[level][i].hash;
                sibling_sums[level] = nodes[level][i].balance;
            }
        }
        current_index /= 2;
    }

    Ok(MerkleProof {
        root_hash: root.hash,
        entry: entries[index].clone(),
        sibling_hashes,
        sibling_sums,
        path_indices,
    })
}
