use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;
use serde::Deserialize;

use summa_solvency::merkle_sum_tree::Entry;

#[derive(Debug, Deserialize)]
pub struct InclusionProof {
    pub leaf_hash: String,
    pub root_hash: String,
    pub proof: String,
}

pub fn generate_leaf_hash<const N_ASSETS: usize>(user_name: String, balances: Vec<usize>) -> Fp
where
    [usize; N_ASSETS + 1]: Sized,
{
    // Convert usize to BigInt for the `Entry` struct
    let balances_big_uint: Vec<BigUint> = balances.into_iter().map(BigUint::from).collect();

    let entry: Entry<N_ASSETS> =
        Entry::new(user_name, balances_big_uint.try_into().unwrap()).unwrap();

    entry.compute_leaf().hash
}
