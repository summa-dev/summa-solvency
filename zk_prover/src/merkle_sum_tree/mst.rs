use crate::merkle_sum_tree::utils::{
    build_merkle_tree_from_leaves, compute_leaves, create_proof, index_of, parse_csv_to_entries,
    verify_proof,
};
use crate::merkle_sum_tree::{Entry, MerkleProof, Node, Tree};
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
/// * `N_BYTES`: Range in which each node balance should lie
#[derive(Debug, Clone)]
pub struct MerkleSumTree<const N_ASSETS: usize, const N_BYTES: usize> {
    root: Node<N_ASSETS>,
    nodes: Vec<Vec<Node<N_ASSETS>>>,
    depth: usize,
    entries: Vec<Entry<N_ASSETS>>,
    is_sorted: bool,
}

impl<const N_ASSETS: usize, const N_BYTES: usize> Tree<N_ASSETS, N_BYTES>
    for MerkleSumTree<N_ASSETS, N_BYTES>
{
    fn root(&self) -> &Node<N_ASSETS> {
        &self.root
    }

    fn depth(&self) -> &usize {
        &self.depth
    }

    fn leaves(&self) -> &[Node<N_ASSETS>] {
        &self.nodes[0]
    }

    fn nodes(&self) -> &[Vec<Node<N_ASSETS>>] {
        &self.nodes
    }

    /// Verifies a MerkleProof
    fn verify_proof(&self, proof: &MerkleProof<N_ASSETS, N_BYTES>) -> bool
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        verify_proof(proof)
    }

    /// Generates a MerkleProof for the user with the given index. No mini tree index is required for a MerkleSumTree.
    fn generate_proof(
        &self,
        user_index: usize,
        mini_tree_index: Option<usize>,
    ) -> Result<MerkleProof<N_ASSETS, N_BYTES>, &'static str> {
        // Check if mini_tree_index_option is provided and return an error if it is
        if mini_tree_index.is_some() {
            return Err("mini_tree_index_option must not be provided for MerkleSumTree type");
        }

        create_proof(user_index, self.depth, &self.nodes, &self.root)
    }
}

impl<const N_ASSETS: usize, const N_BYTES: usize> MerkleSumTree<N_ASSETS, N_BYTES> {
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
        let entries = parse_csv_to_entries::<&str, N_ASSETS, N_BYTES>(path)?;
        Self::build_tree(entries, false)
    }

    /// Builds a Merkle Sum Tree from a CSV file stored at `path`. The MST leaves are sorted by the username byte values. The CSV file must be formatted as follows:
    ///
    /// `username;balances`
    ///
    /// `dxGaEAii;11888,41163`
    pub fn new_sorted(path: &str) -> Result<Self, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        let mut entries = parse_csv_to_entries::<&str, N_ASSETS, N_BYTES>(path)?;

        entries.sort_by(|a, b| a.username().cmp(b.username()));

        Self::build_tree(entries, true)
    }

    fn build_tree(
        entries: Vec<Entry<N_ASSETS>>,
        is_sorted: bool,
    ) -> Result<MerkleSumTree<N_ASSETS, N_BYTES>, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        let depth = (entries.len() as f64).log2().ceil() as usize;

        let mut nodes = vec![];

        let leaves = compute_leaves(&entries);

        let root = build_merkle_tree_from_leaves(&leaves, depth, &mut nodes)?;

        Ok(MerkleSumTree {
            root,
            nodes,
            depth,
            entries,
            is_sorted,
        })
    }

    /// Updates the balances of the entry with the given username and returns the new root of the tree.
    ///
    /// # Arguments
    ///
    /// * `username`: The username of the entry to update
    /// * `new_balances`: The new balances of the entry
    ///
    /// # Returns
    ///
    /// The new root of the tree
    pub fn update_leaf(
        &mut self,
        username: &str,
        new_balances: &[BigUint; N_ASSETS],
    ) -> Result<Node<N_ASSETS>, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        let index = self.index_of_username(username)?;

        // Update the leaf node.
        let updated_leaf = self.entries[index].recompute_leaf(new_balances);
        self.nodes[0][index] = updated_leaf;

        // Recompute the hashes and balances up the tree.
        let mut current_index = index;
        for depth in 1..=self.depth {
            let parent_index = current_index / 2;
            let left_child = &self.nodes[depth - 1][2 * parent_index];
            let right_child = &self.nodes[depth - 1][2 * parent_index + 1];
            self.nodes[depth][parent_index] = Node::<N_ASSETS>::middle(left_child, right_child);
            current_index = parent_index;
        }

        let root = self.nodes[self.depth][0].clone();

        Ok(root)
    }

    pub fn entries(&self) -> &[Entry<N_ASSETS>] {
        &self.entries
    }

    pub fn get_entry(&self, index: usize) -> &Entry<N_ASSETS> {
        &self.entries[index]
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

    /// Returns the index of the leaf with the matching username
    pub fn index_of_username(&self, username: &str) -> Result<usize, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        if !self.is_sorted {
            self.entries
                .iter()
                .enumerate()
                .find(|(_, entry)| entry.username() == username)
                .map(|(index, _)| index)
                .ok_or_else(|| Box::from("Username not found"))
        } else {
            self.entries
                .binary_search_by_key(&username, |entry| entry.username())
                .map_err(|_| Box::from("Username not found"))
        }
    }
}
