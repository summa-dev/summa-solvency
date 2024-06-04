use num_bigint::BigUint;

use crate::utils::big_intify_username;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug)]
pub struct Entry {
    username_as_big_uint: BigUint,
    balance: BigUint,
    username: String,
}

impl Entry {
    pub fn new(username: String, balance: BigUint) -> Result<Self, &'static str> {
        Ok(Entry {
            username_as_big_uint: big_intify_username(&username),
            balance,
            username,
        })
    }

    pub fn init_empty() -> Self {
        Entry {
            username_as_big_uint: BigUint::from(0u32),
            balance: BigUint::from(0u32),
            username: String::new(),
        }
    }

    pub fn balance(&self) -> &BigUint {
        &self.balance
    }

    pub fn username_as_big_uint(&self) -> &BigUint {
        &self.username_as_big_uint
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
