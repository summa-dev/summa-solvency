use crate::merkle_sum_tree::utils::{
    build_merkle_tree_from_entries, create_proof, index_of, parse_csv_to_entries, verify_proof,
};
use crate::merkle_sum_tree::{Entry, MerkleProof, Node};
use num_bigint::BigUint;

/// Merkle Sum Tree Data Structure.
///
/// A Merkle Sum Tree is a binary Merkle Tree with the following properties:
/// * Each Entry of a Merkle Sum Tree is a pair of a username and #N_ASSETS balances.
/// * Each Leaf Node contains a hash and #N_ASSETS balances. The hash is equal to `H(username, balance[0], balance[1], ... balance[N_ASSETS])`.
/// * Each Middle Node contains a hash and #N_ASSETS balances. The hash is equal to `H(LeftChild.hash, LeftChild.balance[0], LeftChild.balance[1], LeftChild.balance[N_ASSETS], RightChild.hash, RightChild.balance[0], RightChild.balance[1], RightChild.balance[N_ASSETS])`. The balances are equal to the sum of the balances of the child nodes per each asset.
/// * The Root Node represents the committed state of the Tree and contains the sum of all the entries' balances per each asset.
///
/// # Type Parameters
///
/// * `N_ASSETS`: The number of assets for each user account
#[derive(Debug, Clone)]
pub struct MerkleSumTree<const N_ASSETS: usize> {
    root: Node<N_ASSETS>,
    nodes: Vec<Vec<Node<N_ASSETS>>>,
    depth: usize,
    entries: Vec<Entry<N_ASSETS>>,
}

impl<const N_ASSETS: usize> MerkleSumTree<N_ASSETS> {
    pub const MAX_DEPTH: usize = 27;

    /// Builds a Merkle Sum Tree from a CSV file stored at `path`. The CSV file must be formatted as follows:
    ///
    /// `username;balances`
    ///
    /// `dxGaEAii;11888,41163`
    pub fn new(path: &str) -> Result<Self, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
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

    /// Returns the nodes stored at the penultimate level of the tree, namely the one before the root
    pub fn penultimate_level_data(
        &self,
    ) -> Result<(&Node<N_ASSETS>, &Node<N_ASSETS>), &'static str> {
        let penultimate_level = self
            .nodes
            .get(self.depth - 1)
            .ok_or("The tree does not have a penultimate level")?;

        Ok((&penultimate_level[0], &penultimate_level[1]))
    }

    /// Returns the index of the user with the given username and balances in the tree
    pub fn index_of(&self, username: &str, balances: [BigUint; N_ASSETS]) -> Option<usize>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        index_of(username, balances, &self.nodes)
    }

    /// Generates a MerkleProof for the user with the given index
    pub fn generate_proof(&self, index: usize) -> Result<MerkleProof<N_ASSETS>, &'static str> {
        create_proof(index, &self.entries, self.depth, &self.nodes, &self.root)
    }

    /// Verifies a MerkleProof
    pub fn verify_proof(&self, proof: &MerkleProof<N_ASSETS>) -> bool
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        verify_proof(proof)
    }
}
