mod entry;
mod mst;
mod node;
mod tests;
mod tree;
pub mod utils;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

/// A struct representing a Merkle Proof.
///
/// Fields:
/// * `entry`: The entry for which the proof is generated
/// * `root`: The root of the Merkle Sum Tree
/// * `sibling_leaf_node_hash_preimage`: The hash preimage of the sibling leaf node. The hash preimage is equal to `[sibling_username, sibling.balance[0], sibling.balance[1], ... sibling.balance[N_CURRENCIES - 1]]`
/// * `sibling_middle_node_hash_preimages`: The hash preimages of the sibling middle nodes. The hash preimage is equal to `[sibling_left_child.balance[0] + sibling_right_child.balance[0], sibling_left_child.balance[1] + sibling_right_child.balance[1], ..., sibling_left_child.balance[N_CURRENCIES - 1] + sibling_right_child.balance[N_CURRENCIES - 1], sibling_left_child.hash, sibling_right_child.hash]`
#[derive(Clone, Debug)]
pub struct MerkleProof<const N_CURRENCIES: usize, const N_BYTES: usize>
where
    [usize; N_CURRENCIES + 1]: Sized,
    [usize; N_CURRENCIES + 2]: Sized,
{
    pub entry: Entry<N_CURRENCIES>,
    pub root: Node<N_CURRENCIES>,
    pub sibling_leaf_node_hash_preimage: [Fp; N_CURRENCIES + 1],
    pub sibling_middle_node_hash_preimages: Vec<[Fp; N_CURRENCIES + 2]>,
    pub path_indices: Vec<Fp>,
}

pub use entry::Entry;
pub use mst::Cryptocurrency;
pub use mst::MerkleSumTree;
pub use node::Node;
pub use tree::Tree;
