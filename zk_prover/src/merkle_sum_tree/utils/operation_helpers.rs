use halo2_proofs::halo2curves::{bn256::Fr as Fp, group::ff::PrimeField};
use num_bigint::BigUint;

/// Return a BigUint representation of the username
pub fn big_intify_username(username: &str) -> BigUint {
    let utf8_bytes = username.as_bytes();
    BigUint::from_bytes_be(utf8_bytes)
}
/// Converts a BigUint to a Field Element
pub fn big_uint_to_fp(big_uint: &BigUint) -> Fp {
    Fp::from_str_vartime(&big_uint.to_str_radix(10)[..]).unwrap()
}

/// Converts a Field element to a BigUint
pub fn fp_to_big_uint(f: Fp) -> BigUint {
    BigUint::from_bytes_le(f.to_bytes().as_slice())
}
