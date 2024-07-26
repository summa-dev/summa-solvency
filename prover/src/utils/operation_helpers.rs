use halo2_proofs::{arithmetic::Field, halo2curves::group::ff::PrimeField};
use num_bigint::BigUint;
use plonkish_backend::{
    poly::multilinear::MultilinearPolynomial,
    util::expression::rotate::{BinaryField, Rotatable},
};

/// Return a BigUint representation of the username
pub fn big_intify_username(username: &str) -> BigUint {
    let utf8_bytes = username.as_bytes();
    BigUint::from_bytes_be(utf8_bytes)
}
/// Converts a BigUint to a Field Element
pub fn big_uint_to_fp<F: Field + PrimeField>(big_uint: &BigUint) -> F {
    F::from_str_vartime(&big_uint.to_str_radix(10)[..]).unwrap()
}

/// Converts a Field element to a BigUint
pub fn fp_to_big_uint<F: Field + PrimeField>(f: &F) -> BigUint {
    BigUint::from_bytes_le(f.to_repr().as_ref())
}

/// Trait to evaluate a multilinear polynomial in binary field as a univariate polynomial
pub trait MultilinearAsUnivariate<F: Field> {
    /// Evaluate the multilinear polynomial as a univariate polynomial
    /// at the point x
    fn evaluate_as_univariate(&self, x: &usize) -> F;
}

impl<F: Field + PrimeField> MultilinearAsUnivariate<F> for MultilinearPolynomial<F> {
    fn evaluate_as_univariate(&self, x: &usize) -> F {
        let x_as_binary_vars = uni_to_multivar_binary_index(x, self.num_vars());
        self.evaluate(x_as_binary_vars.as_slice())
    }
}

/// Converts a single-variable polynomial index into a multivariate index in the binary field
pub fn uni_to_multivar_binary_index<F: Field + PrimeField>(x: &usize, num_vars: usize) -> Vec<F> {
    //The binary field is necessary to map an index to an evaluation point
    let binary_field = BinaryField::new(num_vars).usable_indices();
    //Mapping the univariate point index to a multivariate evaluation point
    let x_in_binary_field = binary_field[*x];
    let x_as_big_uint = BigUint::from(x_in_binary_field);
    let bits = x_as_big_uint.bits();
    let mut result = vec![];
    assert!(
        bits <= num_vars as u64,
        "Number of bits in x exceeds num_vars"
    );

    // Ensure that bits are extended to match num_vars with 0-padding
    for i in 0..num_vars {
        result.push(if x_as_big_uint.bit(i as u64) {
            F::ONE
        } else {
            F::ZERO
        });
    }

    result
}

pub fn calculate_shift_bits<const N_USERS: usize, const N_CURRENCIES: usize>(
) -> Result<usize, String> {
    // Define the maximum number of bits that can be used, based on the modulus in bn254.
    const MAX_ALLOWANCE_BITS: usize = 253;

    // Calculate the maximum number of bits that can be allocated to the user base,
    // taking into account the number of currencies and the bits needed for the balances range check and buffer.
    let maximum_allowance_user_base_bits = (MAX_ALLOWANCE_BITS / N_CURRENCIES) - 64 - 1;

    // Determine the number of bits needed to represent the user base.
    // For example, if `N_USERS` is 1025, the user base bit count would be 11.
    let user_base_bits = N_USERS.next_power_of_two().ilog2() as usize;

    if user_base_bits > maximum_allowance_user_base_bits {
        return Err(format!(
            "The bit count for the user base exceeds the maximum limit of {}",
            maximum_allowance_user_base_bits
        ));
    }

    // Define shift bits: 1 for buffer, bits for user base that not exceed 19, and 64 bits for the balances range check
    let shift_bits: usize = (1 + user_base_bits + 64).try_into().unwrap();

    Ok(shift_bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_shift_bits() {
        {
            // Practical Nnumber of users cases
            const N_USERS: usize = 1 << 28;
            const N_CURRENCIES: usize = 1;

            let result = calculate_shift_bits::<N_USERS, N_CURRENCIES>();
            assert_eq!(result.unwrap(), 93);
            assert_eq!(93 * N_CURRENCIES < 253, true);
        }
        {
            const N_USERS: usize = 1 << 28;
            const N_CURRENCIES: usize = 2;

            let result = calculate_shift_bits::<N_USERS, N_CURRENCIES>();
            assert_eq!(result.unwrap(), 93);
            assert_eq!(93 * N_CURRENCIES < 253, true);
        }
        {
            // Maximum number of user when N_CURRENCIES = 3
            const N_USERS: usize = 1 << 19;
            const N_CURRENCIES: usize = 3;

            let result = calculate_shift_bits::<N_USERS, N_CURRENCIES>();
            assert_eq!(result.unwrap(), 84);
            assert_eq!(84 * N_CURRENCIES < 253, true);
        }
        {
            // Error case in N_CURRENCIES = 2 with infeasible N_USERS
            const N_USERS: usize = 1 << 63;
            const N_CURRENCIES: usize = 2;

            let result = calculate_shift_bits::<N_USERS, N_CURRENCIES>();
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                "The bit count for the user base exceeds the maximum limit of 61"
            );
        }
        {
            const N_USERS: usize = 1 << 63;
            const N_CURRENCIES: usize = 3;

            let result = calculate_shift_bits::<N_USERS, N_CURRENCIES>();
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err(),
                "The bit count for the user base exceeds the maximum limit of 19"
            );
        }
    }
}
