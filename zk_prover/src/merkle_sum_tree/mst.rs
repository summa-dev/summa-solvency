use crate::merkle_sum_tree::utils::{
    build_merkle_tree_from_entries, create_proof, index_of, parse_csv_to_entries, verify_proof,
};
use crate::merkle_sum_tree::{Entry, MerkleProof, Node};
use num_bigint::BigInt;

pub struct MerkleSumTree<const N_ASSETS: usize> {
    root: Node<N_ASSETS>,
    nodes: Vec<Vec<Node<N_ASSETS>>>,
    depth: usize,
    entries: Vec<Entry<N_ASSETS>>,
}

impl<const N_ASSETS: usize> MerkleSumTree<N_ASSETS> {
    pub const MAX_DEPTH: usize = 27;

    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let entries = parse_csv_to_entries(path)?;
        let depth = (entries.len() as f64).log2().ceil() as usize;

        if !(1..=Self::MAX_DEPTH).contains(&depth) {
            return Err(
                "The tree depth must be between 1 and 27, namely it can support 2^27 users at max"
                    .into(),
            );
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

    pub fn root(&self) -> &Node<N_ASSETS> {
        &self.root
    }

    pub fn depth(&self) -> &usize {
        &self.depth
    }

    pub fn leaves(&self) -> &[Node<N_ASSETS>] {
        &self.nodes[0]
    }

    pub fn entries(&self) -> &[Entry<N_ASSETS>] {
        &self.entries
    }

    pub fn index_of(&self, username: &str, balances: [BigInt; N_ASSETS]) -> Option<usize> {
        index_of(username, balances, &self.nodes)
    }

    pub fn penultimate_level_data(
        &self,
    ) -> Result<(&Node<N_ASSETS>, &Node<N_ASSETS>), &'static str> {
        let penultimate_level = self
            .nodes
            .get(self.depth - 1)
            .ok_or("The tree does not have a penultimate level")?;

        Ok((&penultimate_level[0], &penultimate_level[1]))
    }

    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof<N_ASSETS>, &'static str> {
        create_proof(index, &self.entries, self.depth, &self.nodes, &self.root)
    }

    pub fn verify_proof(&self, proof: &MerkleProof<N_ASSETS>) -> bool {
        verify_proof(proof)
    }
}
