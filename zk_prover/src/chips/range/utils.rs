use crate::merkle_sum_tree::utils::fp_to_big_uint;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

/// Converts value Fp to n bytes of bytes in big endian order.
/// If value is decomposed in #bytes which are less than n, then the returned `bytes` are padded with 0s at the most significant bytes.
/// Example:
/// decompose_fp_to_bytes(0x1f2f, 3) -> [0x00, 0x1f, 0x2f]
/// If value is decomposed in #bytes which are greater than n, then the whole bytes of values are returned with a warning.
/// Example:
/// decompose_fp_to_bytes(0x1f2f, 1) -> [0x1f, 0x2f]
pub fn decompose_fp_to_bytes(value: Fp, n: usize) -> Vec<u8> {
    let value_biguint = fp_to_big_uint(value);

    let mut bytes = value_biguint.to_bytes_be();

    // Pad with 0s at the most significant bytes if bytes length is less than n.
    while bytes.len() < n {
        bytes.insert(0, 0);
    }

    if bytes.len() > n {
        println!("Warning: `decompose_fp_to_bytes` value is decomposed in #bytes which are greater than n. It will likely fail the range check constraint in the prover");
    }

    bytes
}

/// Converts a vector of bytes to a vector of running sums of the bytes.
/// Example:
/// running_sums_of_bytes([0x1f, 0x2f, 0x3f, 0x4f]) -> [0x1f, 0x1f2f, 0x1f2f3f, 0x1f2f3f4f]
pub fn running_sums_of_bytes(bytes: Vec<u8>) -> Vec<BigUint> {
    let mut running_sum = BigUint::from(0_u8);
    let mut sums = Vec::with_capacity(bytes.len());

    for &chunk in &bytes {
        running_sum = (running_sum << 8) + chunk as u64;
        sums.push(running_sum.clone());
    }

    sums
}

#[cfg(test)]
mod testing {

    use super::*;

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
        assert_eq!(bytes, vec![0x1f, 0x2f, 0x3f, 0x4f]);
    }

    // convert a 32 bit number in 6 bytes. Should correctly convert to 6 bytes in which the first 2 bytes are 0 padded.
    #[test]
    fn test_decompose_fp_to_bytes_padding() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_bytes(f, 6);
        assert_eq!(bytes, vec![0x00, 0x00, 0x1f, 0x2f, 0x3f, 0x4f]);
    }

    // convert a 32 bit number in 2 bytes. Should convert to 4 bytes and emit a warning
    #[test]
    fn test_decompose_fp_to_bytes_overflow() {
        let f = Fp::from(0x1f2f3f4f);
        let bytes = decompose_fp_to_bytes(f, 2);
        assert_eq!(bytes, vec![0x1f, 0x2f, 0x3f, 0x4f]);
    }

    // convert a 17 bit number in 2 bytes. Should convert to 3 bytes and emit a warning
    #[test]
    fn test_decompose_fp_to_bytes_overflow_2() {
        let f = Fp::from(0x10000);
        let bytes = decompose_fp_to_bytes(f, 2);
        assert_eq!(bytes, vec![0x01, 0x00, 0x00]);
    }

    // Return the running sum from a vector of bytes
    #[test]
    fn test_running_sums_of_bytes() {
        let bytes = vec![0x1f, 0x2f, 0x3f, 0x4f];
        let sums = running_sums_of_bytes(bytes);
        assert_eq!(
            sums,
            vec![
                BigUint::from(0x1f_u64),
                BigUint::from(0x1f2f_u64),
                BigUint::from(0x1f2f3f_u64),
                BigUint::from(0x1f2f3f4f_u64)
            ]
        );
    }
}
