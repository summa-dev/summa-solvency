use crate::merkle_sum_tree::utils::{big_intify_username, big_uint_to_fp, poseidon_entry};
use crate::merkle_sum_tree::Node;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug)]
pub struct Entry<const N_ASSETS: usize> {
    username_to_big_int: BigUint,
    balances: [BigUint; N_ASSETS],
    username: String,
}

impl<const N_ASSETS: usize> Entry<N_ASSETS> {
    pub fn new(username: String, balances: [BigUint; N_ASSETS]) -> Result<Self, &'static str> {
        Ok(Entry {
            username_to_big_int: big_intify_username(&username),
            balances,
            username,
        })
    }

    pub fn init_empty() -> Self {
        let empty_balances: [BigUint; N_ASSETS] = std::array::from_fn(|_| BigUint::from(0u32));

        Entry {
            username_to_big_int: BigUint::from(0u32),
            balances: empty_balances,
            username: "".to_string(),
        }
    }

    pub fn compute_leaf(&self) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        Node {
            hash: poseidon_entry::<N_ASSETS>(
                big_uint_to_fp(&self.username_to_big_int),
                self.balances
                    .iter()
                    .map(big_uint_to_fp)
                    .collect::<Vec<Fp>>()
                    .try_into()
                    .unwrap(),
            ),
            //Map the array of balances using big_int_to_fp:
            balances: self
                .balances
                .iter()
                .map(big_uint_to_fp)
                .collect::<Vec<Fp>>()
                .try_into()
                .unwrap(),
        }
    }

    pub fn balances(&self) -> &[BigUint; N_ASSETS] {
        &self.balances
    }

    pub fn username_to_big_int(&self) -> &BigUint {
        &self.username_to_big_int
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
