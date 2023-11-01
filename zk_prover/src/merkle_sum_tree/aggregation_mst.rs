use crate::merkle_sum_tree::utils::{build_merkle_tree_from_leaves, create_proof, verify_proof};
use crate::merkle_sum_tree::{MerkleProof, MerkleSumTree, Node};

/// Aggregation Merkle Sum Tree Data Structure.
///
/// Starting from a set of "mini" Merkle Sum Trees of equal depth, N_ASSETS and N_BYTES, the Aggregation Merkle Sum Tree is a binary Merkle Tree with the following properties:
/// * Each Leaf of the Aggregation Merkle Sum Tree is the root of a "mini" Merkle Sum Tree made of `hash` and `balances`
///
/// # Type Parameters
///
/// * `N_ASSETS`: The number of assets for each user account
/// * `N_BYTES`: Range in which each node balance should lie
#[derive(Debug, Clone)]
pub struct AggregationMerkleSumTree<const N_ASSETS: usize, const N_BYTES: usize> {
    root: Node<N_ASSETS>,
    nodes: Vec<Vec<Node<N_ASSETS>>>,
    depth: usize,
    mini_trees: Vec<MerkleSumTree<N_ASSETS, N_BYTES>>,
}

impl<const N_ASSETS: usize, const N_BYTES: usize> AggregationMerkleSumTree<N_ASSETS, N_BYTES> {
    /// Builds a AggregationMerkleSumTree from a set of mini MerkleSumTrees
    /// The leaves of the AggregationMerkleSumTree are the roots of the mini MerkleSumTrees
    pub fn new(
        mini_trees: Vec<MerkleSumTree<N_ASSETS, N_BYTES>>,
    ) -> Result<Self, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        // assert that all mini trees have the same depth
        let depth = mini_trees[0].depth();
        assert!(mini_trees.iter().all(|x| x.depth() == depth));

        Self::build_tree(mini_trees)
    }

    fn build_tree(
        mini_trees: Vec<MerkleSumTree<N_ASSETS, N_BYTES>>,
    ) -> Result<AggregationMerkleSumTree<N_ASSETS, N_BYTES>, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        // TO DO: check overflow when building the tree

        // extract all the roots of the mini trees
        let roots = mini_trees
            .iter()
            .map(|x| x.root().clone())
            .collect::<Vec<Node<N_ASSETS>>>();

        let depth = (roots.len() as f64).log2().ceil() as usize;

        let mut nodes = vec![];
        let root = build_merkle_tree_from_leaves(&roots, depth, &mut nodes)?;

        Ok(AggregationMerkleSumTree {
            root,
            nodes,
            depth,
            mini_trees,
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

    pub fn mini_tree(&self, index: usize) -> &MerkleSumTree<N_ASSETS, N_BYTES> {
        &self.mini_trees[index]
    }

    /// Generates a MerkleProof for the user with the given index in the mini tree with the given index
    pub fn generate_proof(
        &self,
        user_index: usize,
        mini_tree_index: usize,
    ) -> Result<MerkleProof<N_ASSETS>, &'static str> {
        let mini_tree = &self.mini_trees[mini_tree_index];

        let partial_proof = create_proof(
            user_index,
            *mini_tree.depth(),
            mini_tree.nodes(),
            mini_tree.root(),
        )?;

        let top_tree_proof = create_proof(mini_tree_index, self.depth, &self.nodes, &self.root)?;

        // Merge the two proofs
        let final_proof = MerkleProof {
            root_hash: self.root.hash,
            leaf: partial_proof.leaf,
            sibling_hashes: [partial_proof.sibling_hashes, top_tree_proof.sibling_hashes].concat(),
            sibling_sums: [partial_proof.sibling_sums, top_tree_proof.sibling_sums].concat(),
            path_indices: [partial_proof.path_indices, top_tree_proof.path_indices].concat(),
        };

        Ok(final_proof)
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
