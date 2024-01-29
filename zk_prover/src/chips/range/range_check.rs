use halo2_proofs::arithmetic::Field;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector};
use halo2_proofs::poly::Rotation;

use std::fmt::Debug;

use super::utils::decompose_fp_to_bytes;

/// Configuration for the Range Check Chip
///
/// # Type Parameters
///
/// * `N_BYTES`: Number of bytes in which the value to be checked should lie
///
/// # Fields
///
/// * `z`: Advice column for the value to be checked and its running sum.
/// * `lookup_enable_selector`: Selector to enable the lookup check.
///
/// Patterned after [halo2_gadgets](https://github.com/privacy-scaling-explorations/halo2/blob/main/halo2_gadgets/src/utilities/decompose_running_sum.rs)
#[derive(Debug, Copy, Clone)]
pub struct RangeCheckConfig<const N_BYTES: usize> {
    z: Column<Advice>,
    lookup_enable_selector: Selector,
}

/// Helper chip that verifies that the value witnessed in a given cell lies within a given range defined by N_BYTES.
/// For example, Let's say we want to constraint 0x1f2f3f4f to be within the range N_BYTES=4.
///
/// * `z(0) = 0x1f2f3f4f`
/// * `z(1) = (0x1f2f3f4f - 0x4f) / 2^8 = 0x1f2f3f`
/// * `z(2) = (0x1f2f3f - 0x3f) / 2^8 = 0x1f2f`
/// * `z(3) = (0x1f2f - 0x2f) / 2^8 = 0x1f`
/// * `z(4) = (0x1f - 0x1f) / 2^8 = 0x00`
///
/// |                | `z`          |
/// | ------------   | -------------|
///  | 0             | `0x1f2f3f4f` |
///  | 1             | `0x1f2f3f`   |
///  | 2             | `0x1f2f`     |
///  | 3             | `0x1f`       |
///  | 4             | `0x00`       |
///
/// The column z contains the witnessed value to be checked at offset 0
/// At offset i, the column z contains the value `z(i+1) = (z(i) - k(i)) / 2^8` (shift right by 8 bits) where k(i) is the i-th decomposition big-endian of `value`
/// The constraints that are enforced are:
/// * `z(i) - 2^8⋅z(i+1) ∈ lookup_u8_table` (enabled by lookup_enable_selector at offset [0, N_BYTES - 1])
/// * `z(N_BYTES) == 0`
#[derive(Debug, Clone)]
pub struct RangeCheckChip<const N_BYTES: usize> {
    config: RangeCheckConfig<N_BYTES>,
}

impl<const N_BYTES: usize> RangeCheckChip<N_BYTES> {
    pub fn construct(config: RangeCheckConfig<N_BYTES>) -> Self {
        Self { config }
    }

    /// Configures the Range Chip
    /// Note: the lookup table should be loaded with values from `0` to `2^8 - 1` otherwise the range check will fail.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        z: Column<Advice>,
        lookup_u8_table: Column<Fixed>,
        lookup_enable_selector: Selector,
    ) -> RangeCheckConfig<N_BYTES> {
        meta.annotate_lookup_any_column(lookup_u8_table, || "LOOKUP_MAXBITS_RANGE");

        meta.lookup_any(
            "range u8 check for difference between each interstitial running sum output",
            |meta| {
                let z_cur = meta.query_advice(z, Rotation::cur());
                let z_next = meta.query_advice(z, Rotation::next());

                let lookup_enable_selector = meta.query_selector(lookup_enable_selector);
                let u8_range = meta.query_fixed(lookup_u8_table, Rotation::cur());

                let diff = z_cur - z_next * Expression::Constant(Fp::from(1 << 8));

                vec![(lookup_enable_selector * diff, u8_range)]
            },
        );

        RangeCheckConfig {
            z,
            lookup_enable_selector,
        }
    }

    /// Assign the running sum to the chip starting from the value within an assigned cell.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign value to perform range check",
            |mut region| {
                // enable the lookup at offset [0, N_BYTES - 1]
                for i in 0..N_BYTES {
                    self.config.lookup_enable_selector.enable(&mut region, i)?;
                }

                // copy `value` to `z_0` at offset 0
                let z_0 = value.copy_advice(
                    || "assign value to be range checked",
                    &mut region,
                    self.config.z,
                    0,
                )?;

                // Decompose the value in #N_BYTES bytes
                let bytes = value
                    .value()
                    .copied()
                    .map(|x| decompose_fp_to_bytes(x, N_BYTES))
                    .transpose_vec(N_BYTES);

                // Initialize empty vector to store running sum values [z_0, ..., z_W].
                let mut zs: Vec<AssignedCell<Fp, Fp>> = vec![z_0.clone()];
                let mut z = z_0;

                // Assign running sum `z_{i+1}` = (z_i - k_i) / (2^8) for i = 0..=N_BYTES - 1.
                let two_pow_k_inv = Value::known(Fp::from(1 << 8).invert().unwrap());

                for (i, byte) in bytes.iter().enumerate() {
                    // z_next = (z_cur - byte) / (2^K)
                    let z_next = {
                        let z_cur_val = z.value().copied();
                        let byte = byte.map(|byte| Fp::from(byte as u64));
                        let z_next_val = (z_cur_val - byte) * two_pow_k_inv;
                        region.assign_advice(
                            || format!("z_{:?}", i + 1),
                            self.config.z,
                            i + 1,
                            || z_next_val,
                        )?
                    };

                    // Update `z`.
                    z = z_next;
                    zs.push(z.clone());
                }

                // Constrain the final running sum output to be zero.
                region.constrain_constant(zs[N_BYTES].cell(), Fp::from(0))?;

                Ok(())
            },
        )
    }
}
