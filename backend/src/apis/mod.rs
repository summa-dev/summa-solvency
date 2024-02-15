pub mod address_ownership;
pub mod csv_parser;
pub mod round;

use ethers::types::U256;
use num_bigint::BigUint;
use num_traits::Num;
use summa_solvency::entry::Entry;

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
    // TODO: Instead of hash of userdata, What should we out to this function?
    let username_big_uint = format!("{:?}", entry.username_as_big_uint());
    U256::from_str_radix(&username_big_uint, 16).unwrap()
}
