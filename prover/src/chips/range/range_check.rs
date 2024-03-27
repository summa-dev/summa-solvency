use crate::chips::range::utils::decompose_fp_to_byte_pairs;
use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Region, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed};
use halo2_proofs::poly::Rotation;
use std::fmt::Debug;

/// Configuration for the Range Check u64 Chip
/// Used to verify that an element lies in the u64 range.
///
/// To prove that the 64-bit balance values would not cause the overflow of the grand sum,
/// let's consider the case at the limit in which we have 2^28 users and all their
/// balances are the maximum possible (namely, 2^64-1):
///
/// >>> 2**28 * (2**64-1)
/// 4951760157141521099328061440
/// >>> n = 4951760157141521099328061440
/// >>> num_bits = n.bit_length()
/// >>> print(num_bits)
/// 92
///
/// The resulting grand sum is only 92 bits. Therefore, we can conclude that the
/// range check of 64 bits on the 2^28 user balances safely removes the risk of overflow
/// in the grand sum calculation.
///
/// # Fields
///
/// * `zs`: Four advice columns - contain the truncated right-shifted values of the element to be checked
/// * `z0`: An advice column - for storing the zero value from the instance column
/// * `instance`: An instance column - zero value provided to the circuit
///
/// # Assumptions
///
/// * The lookup table `range_u16` is by default loaded with values from 0 to 2^16 - 1.
///
/// Patterned after [halo2_gadgets](https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_gadgets/src/utilities/decompose_running_sum.rs)
#[derive(Debug, Copy, Clone)]
pub struct RangeCheckU64Config {
    zs: [Column<Advice>; 4],
}

/// Helper chip that verfiies that the element witnessed in a given cell lies within the u64 range.
/// For example, Let's say we want to constraint 0x1f2f3f4f5f6f7f8f to be a u64.
/// Note that the lookup table `range` is by default loaded with values from 0 to 2^16 - 1.
/// `z` is the advice column that contains the element to be checked.
///
/// `z = 0x1f2f3f4f5f6f7f8f`
/// `zs[0] = (0x1f2f3f4f5f6f7f8f - 0x7f8f) / 2^16 = 0x1f2f3f4f5f6f`
/// `zs[1] = (0x1f2f3f4f5f6f - 0xf5f6f) / 2^16 = 0x1f2f3f4f`
/// `zs[2] = (0x1f2f3f4f - 0x3f4f) / 2^16 = 0x1f2f`
/// `zs[3] = (0x1f2f - 0x1f2f) / 2^16 = 0x00`
///
///  z                  | zs[0]            | zs[1]         | zs[2]        | zs[3]      |
///  ---------          | ----------       | ----------    | ----------   | ---------- |
///  0x1f2f3f4f5f6f7f8f | 0x1f2f3f4f5f6f   | 0x1f2f3f4f    | 0x1f2f       | 0x00       |
///
/// Column zs[0], at offset 0, contains the truncated right-shifted value z - ks[0] / 2^16 (shift right by 16 bits) where ks[0] is the 0-th decomposition big-endian of the element to be checked
/// Column zs[1], at offset 0, contains the truncated right-shifted value zs[0] - ks[1] / 2^16 (shift right by 16 bits) where ks[1] is the 1-th decomposition big-endian of the element to be checked
/// Column zs[2], at offset 0, contains the truncated right-shifted value zs[1] - ks[2] / 2^16 (shift right by 16 bits) where ks[2] is the 2-th decomposition big-endian of the element to be checked
/// Column zs[3], at offset 0, contains the truncated right-shifted value zs[2] - ks[3] / 2^16 (shift right by 16 bits) where ks[3] is the 3-th decomposition big-endian of the element to be checked
///
/// The constraints that are enforced are:
/// 1.
/// z - 2^16⋅zs[0] = ks[0] ∈ range_u16
///
/// 2.
/// for i = 0..=2:
///     zs[i] - 2^16⋅zs[i+1] = ks[i]  ∈ range_u16
///
/// 3.
/// zs[3] == z0
#[derive(Debug, Clone)]
pub struct RangeCheckU64Chip {
    config: RangeCheckU64Config,
}

impl RangeCheckU64Chip {
    pub fn construct(config: RangeCheckU64Config) -> Self {
        Self { config }
    }

    /// Configures the Range Chip
    /// Note: the lookup table should be loaded with values from `0` to `2^16 - 1` otherwise the range check will fail.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        z: Column<Advice>,
        zs: [Column<Advice>; 4],
        range_u16: Column<Fixed>,
    ) -> RangeCheckU64Config {
        // Constraint that the difference between the element to be checked and the 0-th truncated right-shifted value of the element to be within the range.
        // z - 2^16⋅zs[0] = ks[0] ∈ range_u16
        meta.lookup_any(
            "range check in u16 for difference between the element to be checked and the 0-th truncated right-shifted value of the element",
            |meta| {
                let element = meta.query_advice(z, Rotation::cur());

                let zero_truncation = meta.query_advice(zs[0], Rotation::cur());

                let range_u16 = meta.query_fixed(range_u16, Rotation::cur());

                let diff = element - zero_truncation * Expression::Constant(Fp::from(1 << 16));

                vec![(diff, range_u16)]
            },
        );

        // For i = 0..=2: Constraint that the difference between the i-th truncated right-shifted value and the (i+1)-th truncated right-shifted value to be within the range.
        // zs[i] - 2^16⋅zs[i+1] = ks[i]  ∈ range_u16
        for i in 0..=2 {
            meta.lookup_any(
                format!("range check in u16 for difference between the {}-th truncated right-shifted value and the {}-th truncated right-shifted value", i, i+1).as_str(),
                |meta| {
                    let i_truncation = meta.query_advice(zs[i], Rotation::cur());
                    let i_plus_one_truncation = meta.query_advice(zs[i + 1], Rotation::cur());

                    let range_u16 = meta.query_fixed(range_u16, Rotation::cur());

                    let diff = i_truncation - i_plus_one_truncation * Expression::Constant(Fp::from(1 << 16));

                    vec![(diff, range_u16)]
                },
            );
        }

        RangeCheckU64Config { zs }
    }

    /// Assign the truncated right-shifted values of the element to be checked to the corresponding columns zs at offset 0 starting from the element to be checked.
    pub fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        zs: &mut Vec<AssignedCell<Fp, Fp>>,
        element: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        // Decompose the element in 4 byte pairs.
        let ks = element
            .value()
            .copied()
            .map(|x| decompose_fp_to_byte_pairs(x, 4))
            .transpose_vec(4);

        // Initalize an empty vector of cells for the truncated right-shifted values of the element to be checked.
        let mut z = element.clone();

        // Calculate 1 / 2^16
        let two_pow_sixteen_inv = Value::known(Fp::from(1 << 16).invert().unwrap());

        // Perform the assignment of the truncated right-shifted values to zs columns.
        for (i, k) in ks.iter().enumerate() {
            let zs_next = {
                let k = k.map(|byte| Fp::from(u64::from(byte)));
                let zs_next_val = (z.value().copied() - k) * two_pow_sixteen_inv;
                region.assign_advice(
                    || format!("zs_{:?}", i),
                    self.config.zs[i],
                    0,
                    || zs_next_val,
                )?
            };
            // Update `z`.
            z = zs_next;
            zs.push(z.clone());
        }

        Ok(())
    }
}
