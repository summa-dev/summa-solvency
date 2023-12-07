use crate::merkle_sum_tree::utils::big_intify_username;
use crate::merkle_sum_tree::Node;
use num_bigint::BigUint;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug, std::cmp::PartialEq)]
pub struct Entry<const N_CURRENCIES: usize> {
    username_as_big_uint: BigUint,
    balances: [BigUint; N_CURRENCIES],
    username: String,
}

impl<const N_CURRENCIES: usize> Entry<N_CURRENCIES> {
    pub fn new(username: String, balances: [BigUint; N_CURRENCIES]) -> Result<Self, &'static str> {
        Ok(Entry {
            username_as_big_uint: big_intify_username(&username),
            balances,
            username,
        })
    }

    /// Returns a zero entry where the username is 0 and the balances are all 0
    pub fn zero_entry() -> Self {
        let empty_balances: [BigUint; N_CURRENCIES] = std::array::from_fn(|_| BigUint::from(0u32));

        Entry {
            username_as_big_uint: BigUint::from(0u32),
            balances: empty_balances,
            username: "0".to_string(),
        }
    }

    pub fn compute_leaf(&self) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        Node::leaf(&self.username_as_big_uint, &self.balances)
    }

    /// Stores the new balance values
    ///
    /// Returns the updated node
    pub fn recompute_leaf(
        &mut self,
        updated_balances: &[BigUint; N_CURRENCIES],
    ) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        self.balances = updated_balances.clone();
        Node::leaf(&self.username_as_big_uint, updated_balances)
    }

    pub fn balances(&self) -> &[BigUint; N_CURRENCIES] {
        &self.balances
    }

    pub fn username_as_big_uint(&self) -> &BigUint {
        &self.username_as_big_uint
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
