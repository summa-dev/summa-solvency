mod entry;
mod mst;
mod node;
mod tests;
mod tree;
pub mod utils;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

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

pub use entry::Entry;
pub use mst::MerkleSumTree;
pub use node::Node;
pub use tree::Tree;
