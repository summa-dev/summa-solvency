use crate::merkle_sum_tree::utils::{
    build_merkle_tree_from_entries, create_proof, index_of, parse_csv_to_entries, verify_proof,
};
use crate::merkle_sum_tree::{Entry, MerkleProof, Node};
use num_bigint::BigInt;

pub struct MerkleSumTree {
    root: Node,
    nodes: Vec<Vec<Node>>,
    depth: usize,
    entries: Vec<Entry>,
}

impl MerkleSumTree {
    pub const MAX_DEPTH: usize = 32;

    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let entries = parse_csv_to_entries(path)?;
        let depth = (entries.len() as f64).log2().ceil() as usize;

        if !(1..=Self::MAX_DEPTH).contains(&depth) {
            return Err("The tree depth must be between 1 and 32".into());
        }

        let mut nodes = vec![];
        let root = build_merkle_tree_from_entries(&entries, depth, &mut nodes)?;

        Ok(MerkleSumTree {
            root,
            nodes,
            depth,
            entries,
        })
    }

    pub fn root(&self) -> &Node {
        &self.root
    }

    pub fn depth(&self) -> &usize {
        &self.depth
    }

    pub fn leaves(&self) -> &[Node] {
        &self.nodes[0]
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn index_of(&self, username: &str, balance: BigInt) -> Option<usize> {
        index_of(username, balance, &self.nodes)
    }

    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof, &'static str> {
        create_proof(index, &self.entries, self.depth, &self.nodes, &self.root)
    }

    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        verify_proof(proof)
    }
}
