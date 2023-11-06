use crate::merkle_sum_tree::utils::verify_proof;
use crate::merkle_sum_tree::{MerkleProof, Node};

/// A trait representing the basic operations for a Merkle-Sum-like Tree.
pub trait Tree<const N_ASSETS: usize, const N_BYTES: usize> {
    /// Returns a reference to the root node.
    fn root(&self) -> &Node<N_ASSETS>;

    /// Returns the depth of the tree.
    fn depth(&self) -> &usize;

    /// Returns a slice of the leaf nodes.
    fn leaves(&self) -> &[Node<N_ASSETS>];

    /// Returns a slice of the nodes.
    fn nodes(&self) -> &[Vec<Node<N_ASSETS>>];

    /// Generates a MerkleProof for the user with the given index.
    fn generate_proof(
        &self,
        user_index: usize,
    ) -> Result<MerkleProof<N_ASSETS, N_BYTES>, &'static str>;

    /// Verifies a MerkleProof.
    fn verify_proof(&self, proof: &MerkleProof<N_ASSETS, N_BYTES>) -> bool
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        verify_proof(proof)
    }
}
