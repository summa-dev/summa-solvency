use num_bigint::BigUint;

use crate::utils::big_intify_username;

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
            username: String::new(),
        }
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
