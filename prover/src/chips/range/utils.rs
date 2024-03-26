use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

use crate::utils::{big_uint_to_fp, fp_to_big_uint};

/// Converts value Fp to n bytes of bytes in little endian order.
/// If value is decomposed in #bytes which are less than n, then the returned bytes are padded with 0s at the most significant bytes.
/// Example:
/// decompose_fp_to_bytes(0x1f2f3f, 4) -> [0x3f, 0x2f, 0x1f, 0x00]
/// If value is decomposed in #bytes which are greater than n, then the most significant bytes are truncated. A warning is printed.
/// Example:
/// decompose_fp_to_bytes(0x1f2f3f, 2) -> [0x3f, 0x2f]
pub fn decompose_fp_to_bytes(value: Fp, n: usize) -> Vec<u8> {
    let value_biguint = fp_to_big_uint(value);

    let mut bytes = value_biguint.to_bytes_le();

    // Pad with 0s at the most significant bytes if bytes length is less than n.
    while bytes.len() < n {
        bytes.push(0);
    }

    // If the bytes length exceeds n, print a warning and truncate the byte array at the most significant bytes.
    if bytes.len() > n {
        println!("Warning: `decompose_fp_to_bytes` value is decomposed in #bytes which are greater than n. Truncating the output to fit the specified length.");
        bytes.truncate(n);
    }

    bytes
}

/// Converts value Fp to array of n byte pairs in little endian order.
/// If value is decomposed in #byte pairs which are less than n, then the returned byte pairs are padded with 0s at the most significant byte pairs.
/// If value is decomposed in #byte pairs which are greater than n, then the most significant byte pairs are truncated. A warning is printed.
pub fn decompose_fp_to_byte_pairs(value: Fp, n: usize) -> Vec<u16> {
    let value_biguint = fp_to_big_uint(value);
    let mut bytes = value_biguint.to_bytes_le();

    // Ensure the bytes vector has an even length for pairs of bytes.
    if bytes.len() % 2 != 0 {
        bytes.push(0);
    }

    let mut byte_pairs = Vec::new();

    // Iterate over the bytes two at a time.
    for chunk in bytes.chunks(2) {
        // Combine two adjacent bytes into a u16 (2 bytes).
        let pair = (u16::from(chunk[0])) | ((u16::from(chunk[1])) << 8);
        byte_pairs.push(pair);
    }

    // Pad with 0s if the number of byte pairs is less than n.
    while byte_pairs.len() < n {
        byte_pairs.push(0);
    }

    // If the byte pairs length exceeds n, print a warning and truncate.
    if byte_pairs.len() > n {
        println!("Warning: `decompose_fp_to_bytes` value is decomposed in #byte pairs which are greater than n. Truncating the output to fit the specified length.");
        byte_pairs.truncate(n);
    }

    byte_pairs
}

pub fn pow_of_two(by: usize) -> Fp {
    let res = BigUint::from(1u8) << by;
    big_uint_to_fp(&res)
}

#[cfg(test)]
mod testing {

    use crate::utils::fp_to_big_uint;

    use super::*;
    use num_bigint::BigUint;

    #[test]
    fn test_fp_to_big_uint() {
        let f = Fp::from(5);
        let big_uint = fp_to_big_uint(f);
        assert_eq!(big_uint, BigUint::from(5u8));
    }

    // convert a 32 bit number in 4 bytes. Should correctly convert to 4 bytes
    #[test]
    fn test_decompose_fp_to_bytes_no_padding() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_bytes(f, 4);
        assert_eq!(bytes, vec![0x4f, 0x3f, 0x2f, 0x1f]);
    }

    // convert a 32 bit number in 2 byte pairs. Should correctly convert to 2 byte pairs
    #[test]
    fn test_decompose_fp_byte_pairs_no_padding() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_byte_pairs(f, 2);
        assert_eq!(bytes, vec![0x3f4f, 0x1f2f]);
    }

    // convert a 32 bit number in 6 bytes. Should correctly convert to 6 bytes in which the last 2 bytes are 0 padded.
    #[test]
    fn test_decompose_fp_to_bytes_padding() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_bytes(f, 6);
        assert_eq!(bytes, vec![0x4f, 0x3f, 0x2f, 0x1f, 0x00, 0x00]);
    }

    // convert a 32 bit number in 3 byte pairs. Should correctly convert to 3 byte pairs in which the last pair is 0 padded.
    #[test]
    fn test_decompose_fp_to_byte_pairs_padding() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_byte_pairs(f, 3);
        assert_eq!(bytes, vec![0x3f4f, 0x1f2f, 0x00]);
    }

    // convert a 32 bit number in 2 bytes. Should convert to 2 bytes and truncate the most significant bytes and emit a warning
    #[test]
    fn test_decompose_fp_to_bytes_overflow() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_bytes(f, 2);
        assert_eq!(bytes, vec![0x4f, 0x3f]);
    }

    // convert a 32 bit number in 1 byte pair. Should convert to a byte pair and truncate the most significant byte pair and emit a warning
    #[test]
    fn test_decompose_fp_to_byte_pairs_overflow() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_byte_pairs(f, 1);
        assert_eq!(bytes, vec![0x3f4f]);
    }

    // convert a 40 bit number in 2 bytes. Should convert to 2 most significant bytes and truncate the least significant byte
    #[test]
    fn test_decompose_fp_to_bytes_overflow_2() {
        let f = Fp::from(0xf1f2f3f);
        let bytes = decompose_fp_to_bytes(f, 2);
        assert_eq!(bytes, vec![0x3f, 0x2f]);
    }

    #[test]
    fn test_pow_2() {
        let pow = pow_of_two(8);
        assert_eq!(pow, Fp::from(0x100));
        let pow = pow_of_two(72);
        let big_uint = BigUint::from(0x1000000000000000000u128);
        assert_eq!(pow, big_uint_to_fp(&big_uint));
    }
}
