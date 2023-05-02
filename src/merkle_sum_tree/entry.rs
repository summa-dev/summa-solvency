use halo2_proofs::halo2curves::bn256::{Fr as Fp};

use crate::merkle_sum_tree::utils::{big_intify_username, poseidon};
use crate::merkle_sum_tree::Node;

#[derive(Default, Clone, Debug)]
pub struct Entry {
    username_to_big_int: u64,
    balance: u64,
    username: String,
}

impl Entry {
    pub const ZERO_ENTRY: Entry = Entry {
        username_to_big_int: 0,
        balance: 0,
        username: String::new(),
    };

    pub fn new(username: String, balance: u64) -> Result<Self, &'static str> {
        // if balance < 0 {
        //     return Err("entry balance can't be negative");
        // }

        Ok(Entry {
            username_to_big_int: big_intify_username(&username),
            balance,
            username,
        })
    }

    pub fn compute_leaf(&self) -> Node {
        Node {
            hash: poseidon(
                Fp::from(self.username_to_big_int),
                Fp::from(self.balance),
                Fp::from(0),
                Fp::from(0),
            ),
            balance: Fp::from(self.balance),
        }
    }

    // Getters
    pub fn balance(&self) -> u64 {
        self.balance
    }

    pub fn username_to_big_int(&self) -> u64 {
        self.username_to_big_int
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
