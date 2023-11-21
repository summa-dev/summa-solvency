use crate::merkle_sum_tree::big_uint_to_fp;
use crate::merkle_sum_tree::{Entry, MerkleProof, Node};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

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

    fn get_entry(&self, index: usize) -> &Entry<N_ASSETS>;

    fn entries(&self) -> &[Entry<N_ASSETS>];

    /// Returns the hash preimage of a middle node.
    fn get_middle_node_hash_preimage(
        &self,
        level: usize,
        index: usize,
    ) -> Result<[Fp; N_ASSETS + 2], Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 2]: Sized,
    {
        if level == 0 || level > *self.depth() {
            return Err(Box::from("Invalid depth"));
        }

        self.nodes()
            .get(level)
            .and_then(|layer| layer.get(index))
            .ok_or_else(|| Box::<dyn std::error::Error>::from("Node not found"))?;

        // Assuming the left and right children are stored in order
        let left_child = &self.nodes()[level - 1][2 * index];
        let right_child = &self.nodes()[level - 1][2 * index + 1];

        // Constructing preimage
        let mut preimage = [Fp::zero(); N_ASSETS + 2];

        // for each balance in the left and right child, add them together and store in preimage
        for (i, balance) in preimage.iter_mut().enumerate().take(N_ASSETS) {
            *balance = left_child.balances[i] + right_child.balances[i];
        }

        // Add left and right child hashes to preimage
        preimage[N_ASSETS] = left_child.hash;
        preimage[N_ASSETS + 1] = right_child.hash;

        Ok(preimage)
    }

    /// Returns the hash preimage of a leaf node.
    fn get_leaf_node_hash_preimage(
        &self,
        index: usize,
    ) -> Result<[Fp; N_ASSETS + 1], Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        // Fetch entry corresponding to index
        let entry = self
            .entries()
            .get(index)
            .ok_or_else(|| Box::<dyn std::error::Error>::from("Node not found"))?;

        // Constructing preimage
        let mut preimage = [Fp::zero(); N_ASSETS + 1];

        // Add username to preimage
        preimage[0] = big_uint_to_fp(entry.username_as_big_uint());

        // Add balances to preimage
        for (i, balance) in preimage.iter_mut().enumerate().skip(1).take(N_ASSETS) {
            *balance = big_uint_to_fp(&entry.balances()[i - 1]);
        }

        Ok(preimage)
    }

    /// Generates a MerkleProof for the user with the given index.
    fn generate_proof(
        &self,
        index: usize,
    ) -> Result<MerkleProof<N_ASSETS, N_BYTES>, Box<dyn std::error::Error>>
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; N_ASSETS + 2]: Sized,
    {
        let nodes = self.nodes();
        let depth = *self.depth();
        let root = self.root();

        if index >= nodes[0].len() {
            return Err(Box::from("Index out of bounds"));
        }

        let mut sibling_hashes = vec![Fp::zero(); depth];
        let mut sibling_sums = vec![[Fp::zero(); N_ASSETS]; depth];
        let mut sibling_node_hash_preimages = Vec::with_capacity(depth);
        let mut path_indices = vec![Fp::zero(); depth];
        let mut current_index = index;

        let leaf = &nodes[0][index];
        let sibling_leaf_hash_preimage = self.get_leaf_node_hash_preimage(index)?;

        for level in 0..depth {
            let position = current_index % 2;
            let sibling_index = current_index - position + (1 - position);

            if sibling_index < nodes[level].len() {
                let sibling_node = &nodes[level][sibling_index];

                sibling_hashes[level] = sibling_node.hash;
                sibling_sums[level] = sibling_node.balances;

                if level > 0 {
                    // Fetch hash preimage for sibling middle nodes
                    let sibling_node_preimage =
                        self.get_middle_node_hash_preimage(level, sibling_index / 2)?;
                    sibling_node_hash_preimages.push(sibling_node_preimage);
                }
            }

            path_indices[level] = Fp::from(position as u64);
            current_index /= 2;
        }

        Ok(MerkleProof {
            leaf: leaf.clone(),
            root: root.clone(),
            sibling_hashes,
            sibling_sums,
            sibling_leaf_hash_preimage,
            sibling_node_hash_preimages,
            path_indices,
        })
    }

    /// Verifies a MerkleProof.
    fn verify_proof(&self, proof: &MerkleProof<N_ASSETS, N_BYTES>) -> bool
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; N_ASSETS + 2]: Sized,
    {
        let mut node = proof.leaf.clone();

        for i in 0..proof.sibling_hashes.len() {
            let sibling_node = Node {
                hash: proof.sibling_hashes[i],
                balances: proof.sibling_sums[i],
            };

            if proof.path_indices[i] == 0.into() {
                node = Node::middle(&node, &sibling_node);
            } else {
                node = Node::middle(&sibling_node, &node);
            }
        }

        proof.root.hash == node.hash && proof.root.balances == node.balances
    }
}
