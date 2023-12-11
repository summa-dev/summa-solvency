use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed};
use halo2_proofs::poly::Rotation;

use std::fmt::Debug;

use crate::chips::range::utils::decompose_fp_to_bytes;

/// Configuration for the Range Check Chip
///
/// # Type Parameters
///
/// * `N_BYTES`: Number of bytes in which the element to be checked should lie
///
/// # Fields
///
/// * `z`: Advice column - contains the element to be checked
/// * `zs`: Advice columns for the truncated right-shifted values of the element to be checked
/// * `range`: Fixed column for the lookup table. It contains the values from 0 to 2^8 - 1.
///
/// Patterned after [halo2_gadgets](https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_gadgets/src/utilities/decompose_running_sum.rs)
#[derive(Debug, Copy, Clone)]
pub struct RangeCheckConfig<const N_BYTES: usize> {
    zs: [Column<Advice>; N_BYTES],
    range: Column<Fixed>,
}

/// Helper chip that verfiies that the element witnessed in a given cell lies within a given range defined by N_BYTES.
/// For example, Let's say we want to constraint 0x1f2f3f4f to be within the range N_BYTES=4.
///
/// `z = 0x1f2f3f4f`
/// `zs[0] = (0x1f2f3f4f - 0x4f) / 2^8 = 0x1f2f3f`
/// `zs[1] = (0x1f2f3f - 0x3f) / 2^8 = 0x1f2f`
/// `zs[2] = (0x1f2f - 0x2f) / 2^8 = 0x1f`
/// `zs[3] = (0x1f - 0x1f) / 2^8 = 0x00`
///
///  z          | zs[0]      | zs[1]      | zs[2]      | zs[3]      |
///  ---------  | ---------- | ---------- | ---------- | ---------- |
///  0x1f2f3f4f | 0x1f2f3f   | 0x1f2f     | 0x1f       | 0x00       |
///
/// Column zs[0], at offset 0, contains the truncated right-shifted value z - ks[0] / 2^8 (shift right by 8 bits) where ks[0] is the 0-th decomposition big-endian of the element to be checked
/// Column zs[1], at offset 0, contains the truncated right-shifted value zs[0] - ks[1] / 2^8 (shift right by 8 bits) where ks[1] is the 1-th decomposition big-endian of the element to be checked
/// Column zs[2], at offset 0, contains the truncated right-shifted value zs[1] - ks[2] / 2^8 (shift right by 8 bits) where ks[2] is the 2-th decomposition big-endian of the element to be checked
/// Column zs[3], at offset 0, contains the truncated right-shifted value zs[2] - ks[3] / 2^8 (shift right by 8 bits) where ks[3] is the 3-th decomposition big-endian of the element to be checked
///
/// The contraints that are enforced are:
/// 1.
/// - z - 2^8⋅zs[0] = kz[0] ∈ lookup_u8
///
/// 2.
/// for i = 0..=N_BYTES - 2:
/// - zs[i] - 2^8⋅zs[i+1] = kz[i]  ∈ lookup_u8
///
/// 3.
/// - zs[N_BYTES - 1] == 0
#[derive(Debug, Clone)]
pub struct RangeCheckChip<const N_BYTES: usize> {
    config: RangeCheckConfig<N_BYTES>,
}

impl<const N_BYTES: usize> RangeCheckChip<N_BYTES> {
    pub fn construct(config: RangeCheckConfig<N_BYTES>) -> Self {
        Self { config }
    }

    /// Configures the Range Chip
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        z: Column<Advice>,
        zs: [Column<Advice>; N_BYTES],
        range: Column<Fixed>,
    ) -> RangeCheckConfig<N_BYTES> {
        meta.annotate_lookup_any_column(range, || "LOOKUP_MAXBITS_RANGE");

        // Constraint that the difference between the element to be checked and the 0-th truncated right-shifted value of the element to be within the range.
        // z - 2^8⋅zs[0] = kz[0] ∈ lookup_u8
        meta.lookup_any(
            "range u8 check for difference between the element to be checked and the 0-th truncated right-shifted value of the element",
            |meta| {
                let element = meta.query_advice(z, Rotation::cur());
                let zero_truncation = meta.query_advice(zs[0], Rotation::cur());

                let u8_range = meta.query_fixed(range, Rotation::cur());

                let diff = element - zero_truncation * Expression::Constant(Fp::from(1 << 8));

                vec![(diff, u8_range)]
            },
        );

        // For i = 0..=N_BYTES - 2: Constraint that the difference between the i-th truncated right-shifted value and the (i+1)-th truncated right-shifted value to be within the range.
        // - zs[i] - 2^8⋅zs[i+1] = kz[i]  ∈ lookup_u8
        for i in 0..=N_BYTES - 2 {
            meta.lookup_any(
                format!("range u8 check for difference between the {}-th truncated right-shifted value and the {}-th truncated right-shifted value", i, i+1).as_str(),
                |meta| {
                    let i_truncation = meta.query_advice(zs[i], Rotation::cur());
                    let i_plus_one_truncation = meta.query_advice(zs[i + 1], Rotation::cur());

                    let u8_range = meta.query_fixed(range, Rotation::cur());

                    let diff = i_truncation - i_plus_one_truncation * Expression::Constant(Fp::from(1 << 8));

                    vec![(diff, u8_range)]
                },
            );
        }

        RangeCheckConfig { zs, range }
    }

    /// Assign the truncated right-shifted values of the element to be checked to the corresponding columns zs at offset 0 starting from the element to be checked.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        element: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign values to zs column",
            |mut region| {
                // Decompose the element in #N_BYTES bytes
                let ks = element
                    .value()
                    .copied()
                    .map(|x| decompose_fp_to_bytes(x, N_BYTES))
                    .transpose_vec(N_BYTES);

                // Initalize an empty vector of cells for the truncated right-shifted values of the element to be checked.
                let mut zs = Vec::with_capacity(N_BYTES);
                let mut z = element.clone();

                // Calculate 1 / 2^8
                let two_pow_eight_inv = Value::known(Fp::from(1 << 8).invert().unwrap());

                // Perform the assignment of the truncated right-shifted values to zs columns.
                for (i, k) in ks.iter().enumerate() {
                    let zs_next = {
                        let k = k.map(|byte| Fp::from(byte as u64));
                        let zs_next_val = (z.value().copied() - k) * two_pow_eight_inv;
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

                // Constrain the final running sum output to be zero.
                region.constrain_constant(zs[N_BYTES - 1].cell(), Fp::from(0))?;

                Ok(())
            },
        )
    }

    /// Loads the lookup table with values from `0` to `2^8 - 1`
    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        let range = 1 << (8);

        layouter.assign_region(
            || format!("load range check table of {} bits", 8),
            |mut region| {
                for i in 0..range {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        self.config.range,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
