use crate::merkle_sum_tree::utils::big_intify_username;
use crate::merkle_sum_tree::utils::big_uint_to_fp;
use crate::merkle_sum_tree::Node;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug)]
pub struct Entry<const N_ASSETS: usize> {
    username_as_big_uint: BigUint,
    balances: [BigUint; N_ASSETS],
    username: String,
}

impl<const N_ASSETS: usize> Entry<N_ASSETS> {
    pub fn new(username: String, balances: [BigUint; N_ASSETS]) -> Result<Self, &'static str> {
        Ok(Entry {
            username_as_big_uint: big_intify_username(&username),
            balances,
            username,
        })
    }

    pub fn init_empty() -> Self {
        let empty_balances: [BigUint; N_ASSETS] = std::array::from_fn(|_| BigUint::from(0u32));

        Entry {
            username_as_big_uint: BigUint::from(0u32),
            balances: empty_balances,
            username: "".to_string(),
        }
    }

    pub fn compute_leaf(&self) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        let mut hash_preimage = [Fp::zero(); N_ASSETS + 1];
        hash_preimage[0] = big_uint_to_fp(&self.username_as_big_uint);
        for (i, balance) in hash_preimage.iter_mut().enumerate().skip(1) {
            *balance = big_uint_to_fp(&self.balances[i - 1]);
        }

        Node::leaf_node_from_preimage(hash_preimage)
    }

    /// Stores the new balance values
    ///
    /// Returns the updated node
    pub fn recompute_leaf(&mut self, updated_balances: &[BigUint; N_ASSETS]) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        self.balances = updated_balances.clone();

        let mut hash_preimage = [Fp::zero(); N_ASSETS + 1];
        hash_preimage[0] = big_uint_to_fp(&self.username_as_big_uint);
        for (i, balance) in hash_preimage.iter_mut().enumerate().skip(1) {
            *balance = big_uint_to_fp(&self.balances[i - 1]);
        }
        Node::leaf_node_from_preimage(hash_preimage)
    }

    pub fn balances(&self) -> &[BigUint; N_ASSETS] {
        &self.balances
    }

    pub fn username_as_big_uint(&self) -> &BigUint {
        &self.username_as_big_uint
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
