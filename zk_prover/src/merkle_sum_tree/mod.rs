mod aggregation_mst;
mod entry;
mod mst;
mod node;
mod tests;
pub mod utils;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

#[derive(Clone, Debug)]
pub struct MerkleProof<const N_ASSETS: usize> {
    pub root_hash: Fp,
    pub entry: Entry<N_ASSETS>,
    pub sibling_hashes: Vec<Fp>,
    pub sibling_sums: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
}

#[derive(Clone, Debug)]
pub struct TopTreeMerkleProof<const N_ASSETS: usize> {
    pub root_hash: Fp,
    pub sibling_hashes: Vec<Fp>,
    pub sibling_sums: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
}

pub use aggregation_mst::AggregationMerkleSumTree;
pub use entry::Entry;
pub use mst::MerkleSumTree;
pub use node::Node;
pub use utils::{big_intify_username, big_uint_to_fp};
