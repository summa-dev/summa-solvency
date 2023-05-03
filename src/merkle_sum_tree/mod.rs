mod entry;
mod mst;
mod utils;
mod tests;
use halo2_proofs::halo2curves::bn256::{Fr as Fp};

#[derive(Default, Clone, Debug)]
pub struct MerkleProof {
    pub root_hash: Fp,
    pub entry: Entry,
    pub sibling_hashes: Vec<Fp>,
    pub sibling_sums: Vec<Fp>,
    pub path_indices: Vec<Fp>,
}

#[derive(Default, Clone, Debug)]
pub struct Node {
    pub hash: Fp,
    pub balance: Fp,
}

pub use entry::Entry;
pub use mst::MerkleSumTree;
pub use utils::{big_intify_username, big_int_to_fp};


