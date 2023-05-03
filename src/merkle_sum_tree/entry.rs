use halo2_proofs::halo2curves::bn256::{Fr as Fp};

use crate::merkle_sum_tree::utils::{big_intify_username, poseidon, big_int_to_fp};
use crate::merkle_sum_tree::Node;
use num_bigint::{BigInt};

#[derive(Default, Clone, Debug)]
pub struct Entry {
    username_to_big_int: BigInt,
    balance: BigInt,
    username: String,
}

impl Entry {

    pub fn new(username: String, balance: BigInt) -> Result<Self, &'static str> {

        Ok(Entry {
            username_to_big_int: big_intify_username(&username),
            balance,
            username,
        })
    }

    pub fn compute_leaf(&self) -> Node {
        Node {
            hash: poseidon(
                big_int_to_fp(&self.username_to_big_int),
                big_int_to_fp(&self.balance),
                Fp::from(0),
                Fp::from(0),
            
            ),
            balance: big_int_to_fp(&self.balance),
        }
    }

    // Getters
    pub fn balance(&self) -> &BigInt {
        &self.balance
    }

    pub fn username_to_big_int(&self) -> &BigInt {
        &self.username_to_big_int
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
