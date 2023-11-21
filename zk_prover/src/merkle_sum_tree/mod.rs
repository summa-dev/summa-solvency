mod entry;
mod mst;
mod node;
mod tests;
mod tree;
pub mod utils;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

/// # Fields
///
/// * `entry`: The entry to be verified inclusion of.
/// * `path_indices`: The boolean indices of the path elements from the leaf to the root. 0 indicates that the element is on the right to the path, 1 indicates that the element is on the left to the path. The length of this vector is LEVELS
/// * `sibling_leaf_node_hash_preimage`: The preimage of the hash that corresponds to the Sibling Leaf Node (part of the Merkle Proof).
/// * `sibling_middle_node_hash_preimages`: The preimages of the hashes that corresponds to the Sibling Middle Nodes (part of the Merkle Proof).  
/// * `root`: The root of the Merkle Sum Tree

#[derive(Clone, Debug)]
pub struct MerkleProof<const N_ASSETS: usize, const N_BYTES: usize>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
    pub entry: Entry<N_ASSETS>,
    pub root: Node<N_ASSETS>,
    pub sibling_leaf_node_hash_preimage: [Fp; N_ASSETS + 1],
    pub sibling_middle_node_hash_preimages: Vec<[Fp; N_ASSETS + 2]>,
    pub path_indices: Vec<Fp>,
}

// Add iniit_empyt method to MerkleProof
impl<const N_ASSETS: usize, const N_BYTES: usize> MerkleProof<N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
    pub fn init_empty() -> MerkleProof<N_ASSETS, N_BYTES> {
        MerkleProof {
            entry: Entry::init_empty(),
            root: Node::init_empty(),
            sibling_leaf_node_hash_preimage: [Fp::zero(); N_ASSETS + 1],
            sibling_middle_node_hash_preimages: Vec::new(),
            path_indices: Vec::new(),
        }
    }
}

pub use entry::Entry;
pub use mst::MerkleSumTree;
pub use node::Node;
pub use tree::Tree;
pub use utils::{big_intify_username, big_uint_to_fp};
