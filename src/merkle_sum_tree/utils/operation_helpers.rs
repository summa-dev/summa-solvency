use num_bigint::{BigInt, Sign};
use halo2_proofs::halo2curves::{bn256::{Fr as Fp}, group::ff::PrimeField};

// Return a BigUint representation of the username
pub fn big_intify_username(username: &str) -> BigInt {
    let utf8_bytes = username.as_bytes();
    BigInt::from_bytes_be(Sign::Plus, utf8_bytes)
}

pub fn big_int_to_fp(big_int: &BigInt) -> Fp {
    Fp::from_str_vartime(&big_int.to_str_radix(10)[..]).unwrap()
}

#[cfg(test)]
mod tests {

    use num_bigint::{ToBigInt, BigInt};
    use super::big_int_to_fp;

    #[test]
    fn test_big_int_conversion() {

        let big_int = 3.to_bigint().unwrap();
        let fp = big_int_to_fp(&big_int);

        assert_eq!(fp, 3.into());

        let big_int_over_64 = (18446744073709551616_i128).to_bigint().unwrap();
        let fp_2 = big_int_to_fp(&big_int_over_64);

        let big_int_to_bytes = {
            let (_, mut bytes) = BigInt::to_bytes_le(&big_int_over_64);
            bytes.resize(32, 0);
            bytes
        };

        assert_eq!(fp_2.to_bytes().to_vec(), big_int_to_bytes);

        let fp_3 = fp_2 - fp;
        assert_eq!(fp_3, 18446744073709551613.into());
    }
}
