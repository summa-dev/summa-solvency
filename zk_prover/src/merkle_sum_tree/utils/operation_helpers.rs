use halo2_proofs::halo2curves::{bn256::Fr as Fp, group::ff::PrimeField};
use num_bigint::{BigInt, Sign};

/// Return a BigInt representation of the username
pub fn big_intify_username(username: &str) -> BigInt {
    let utf8_bytes = username.as_bytes();
    BigInt::from_bytes_be(Sign::Plus, utf8_bytes)
}
/// Converts a BigInt to a Field Element
pub fn big_int_to_fp(big_int: &BigInt) -> Fp {
    Fp::from_str_vartime(&big_int.to_str_radix(10)[..]).unwrap()
}
