use num_bigint::BigUint;

use crate::utils::big_intify_username;

/// An entry in the Merkle Sum Tree from the database of the CEX.
/// It contains the username and the balances of the user.
#[derive(Clone, Debug)]
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

    pub fn init_empty() -> Self {
        let empty_balances: [BigUint; N_CURRENCIES] = std::array::from_fn(|_| BigUint::from(0u32));

        Entry {
            username_as_big_uint: BigUint::from(0u32),
            balances: empty_balances,
            username: String::new(),
        }
    }

    pub fn balances(&self) -> &[BigUint; N_CURRENCIES] {
        &self.balances
    }

    pub fn concatenated_balance(&self) -> BigUint {
        let mut concatenated_balance = BigUint::from(0u32);

        for (i, balance) in self.balances.iter().enumerate() {
            // Shift bits: 1 for buffer; 19 is highest bit for two power of userbase; 64 is for the maximum range check limit
            concatenated_balance += balance << ((1 + 19 + 64) * i);
        }

        concatenated_balance
    }

    pub fn username_as_big_uint(&self) -> &BigUint {
        &self.username_as_big_uint
    }

    pub fn username(&self) -> &str {
        &self.username
    }
}
