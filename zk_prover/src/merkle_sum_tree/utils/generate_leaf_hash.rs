use ethers::types::U256;
use num_bigint::BigUint;

use crate::merkle_sum_tree::Entry;

pub fn generate_leaf_hash<const N_ASSETS: usize>(user_name: String, balances: Vec<usize>) -> U256
where
    [usize; N_ASSETS + 1]: Sized,
{
    // Convert usize to BigInt for the `Entry` struct
    let balances_big_uint: Vec<BigUint> = balances.into_iter().map(BigUint::from).collect();

    let entry: Entry<N_ASSETS> =
        Entry::new(user_name, balances_big_uint.try_into().unwrap()).unwrap();

    // Convert Fp to U256
    let hash_str = format!("{:?}", entry.compute_leaf().hash);
    U256::from_str_radix(&hash_str, 16).unwrap()
}
