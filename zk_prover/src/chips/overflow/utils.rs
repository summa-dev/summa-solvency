use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr as Fp};
use num_bigint::BigUint;

/// Converts a Field element to a BigUint
fn fp_to_big_uint(f: Fp) -> BigUint {
    BigUint::from_bytes_le(f.to_bytes().as_slice())
}

/// Converts a Value<Fp> to a BigUint
pub fn value_fp_to_big_uint(v: Value<Fp>) -> BigUint {
    let mut inner_value = Fp::zero();
    v.as_ref().map(|f| inner_value = inner_value.add(f));

    fp_to_big_uint(inner_value)
}

/// Decomposes a BigUint into a vector of Field elements
/// `number_of_limbs` is the number of chunks to split the BigUint into
/// `bit_len` is the number of bits in each chunk
pub fn decompose_bigint_to_ubits(e: &BigUint, number_of_limbs: usize, bit_len: usize) -> Vec<Fp> {
    debug_assert!(bit_len <= 64);

    let mut e = e.iter_u64_digits();
    let mask: u64 = (1u64 << bit_len) - 1u64;
    let mut u64_digit = e.next().unwrap_or(0);
    let mut rem = 64;
    (0..number_of_limbs)
        .map(|_| match rem.cmp(&bit_len) {
            core::cmp::Ordering::Greater => {
                let limb = u64_digit & mask;
                u64_digit >>= bit_len;
                rem -= bit_len;
                Fp::from(limb)
            }
            core::cmp::Ordering::Equal => {
                let limb = u64_digit & mask;
                u64_digit = e.next().unwrap_or(0);
                rem = 64;
                Fp::from(limb)
            }
            core::cmp::Ordering::Less => {
                let mut limb = u64_digit;
                u64_digit = e.next().unwrap_or(0);
                limb |= (u64_digit & ((1 << (bit_len - rem)) - 1)) << rem;
                u64_digit >>= bit_len - rem;
                rem += 64 - bit_len;
                Fp::from(limb)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decompose_modulus() {
        // bn254 modulus, r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
        let max_minus_one = Fp::from_raw([
            0x43e1f593ef000000,
            0x2833e84879b97091,
            0xb85045b68181585d,
            0x30644e72e131a029,
        ]);

        let biguint_max = fp_to_big_uint(max_minus_one);
        let decomposed_max = decompose_bigint_to_ubits(&biguint_max, 22, 12);

        let expected_values = [
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "0x00000000000000000000000000000000000000000000000000000000000003ef",
            "0x0000000000000000000000000000000000000000000000000000000000000f59",
            "0x00000000000000000000000000000000000000000000000000000000000003e1",
            "0x0000000000000000000000000000000000000000000000000000000000000914",
            "0x0000000000000000000000000000000000000000000000000000000000000970",
            "0x000000000000000000000000000000000000000000000000000000000000079b",
            "0x0000000000000000000000000000000000000000000000000000000000000848",
            "0x000000000000000000000000000000000000000000000000000000000000033e",
            "0x0000000000000000000000000000000000000000000000000000000000000d28",
            "0x0000000000000000000000000000000000000000000000000000000000000585",
            "0x0000000000000000000000000000000000000000000000000000000000000181",
            "0x0000000000000000000000000000000000000000000000000000000000000b68",
            "0x0000000000000000000000000000000000000000000000000000000000000045",
            "0x0000000000000000000000000000000000000000000000000000000000000b85",
            "0x0000000000000000000000000000000000000000000000000000000000000029",
            "0x000000000000000000000000000000000000000000000000000000000000031a",
            "0x00000000000000000000000000000000000000000000000000000000000002e1",
            "0x00000000000000000000000000000000000000000000000000000000000004e7",
            "0x0000000000000000000000000000000000000000000000000000000000000064",
            "0x0000000000000000000000000000000000000000000000000000000000000003",
        ];

        for (i, &expected) in expected_values.iter().enumerate() {
            assert_eq!(format!("{:?}", decomposed_max[i]), expected);
        }
    }

    #[test]
    fn decompose_250bits() {
        // 1 << 251 = 0x800000000000000000000000000000000000000000000000000000000000000
        //       -1 = 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        let max_u250 = Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x07ffffffffffffff,
        ]);

        let biguint_max_u250 = fp_to_big_uint(max_u250);
        let decomposed = decompose_bigint_to_ubits(&biguint_max_u250, 10, 25);

        let expected = "0x0000000000000000000000000000000000000000000000000000000001ffffff";
        for value in decomposed.iter() {
            assert_eq!(format!("{:?}", value), expected);
        }
    }

    #[test]
    fn decompose_251bits() {
        // 1 << 252 = 0x1000000000000000000000000000000000000000000000000000000000000000
        //      - 1 = 0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        let max_u251 = Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]);

        let biguint_max_u251 = fp_to_big_uint(max_u251);
        let decomposed = decompose_bigint_to_ubits(&biguint_max_u251, 21, 12);

        let expected = "0x0000000000000000000000000000000000000000000000000000000000000fff";
        for value in decomposed.iter() {
            assert_eq!(format!("{:?}", value), expected);
        }
    }
}
