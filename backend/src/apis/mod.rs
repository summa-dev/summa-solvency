pub mod address_ownership;
pub mod csv_parser;
pub mod round;

use ethers::types::U256;
use num_bigint::BigUint;
use num_traits::Num;
use summa_solvency::merkle_sum_tree::Entry;

pub fn leaf_hash_from_inputs<const N_CURRENCIES: usize>(
    username: String,
    balances: Vec<String>,
) -> U256
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    // Convert balances to BigUint
    let balances: Vec<BigUint> = balances
        .iter()
        .map(|balance| BigUint::from_str_radix(balance, 10).unwrap())
        .collect();

    let entry: Entry<N_CURRENCIES> = Entry::new(username, balances.try_into().unwrap()).unwrap();

    // Convert Fp to U256
    let hash_str = format!("{:?}", entry.compute_leaf().hash);
    U256::from_str_radix(&hash_str, 16).unwrap()
}
