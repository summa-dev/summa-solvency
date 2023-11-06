mod entry;
mod mst;
mod node;
mod tests;
mod tree;
pub mod utils;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

#[derive(Clone, Debug)]
pub struct MerkleProof<const N_ASSETS: usize, const N_BYTES: usize> {
    pub leaf: Node<N_ASSETS>,
    pub root_hash: Fp,
    pub sibling_hashes: Vec<Fp>,
    pub sibling_sums: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
}

pub use entry::Entry;
pub use mst::MerkleSumTree;
pub use node::Node;
pub use tree::Tree;
pub use utils::{big_intify_username, big_uint_to_fp};
