use crate::chips::range::utils::{decompose_fp_to_bytes, running_sums_of_bytes};
use crate::merkle_sum_tree::big_uint_to_fp;
use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use std::fmt::Debug;

/// Configuration for the Range Check Chip
///
/// # Type Parameters
///
/// * `N_BYTES`: Number of bytes in which the value to be checked should lie
///
/// # Fields
///
/// * `value`: Advice column for the value to be checked.
/// * `decomposed_value`: Advice column for storing the bytes of the decomposed value.
/// * `running_sum`: Advice column for storing the running sum of the decomposed value.
/// * `range`: Fixed column for the range table.
/// * `toggle_running_sum_check`: Selector to toggle the polynomial constraint between the running sum and the decomposed value.
/// * `toggle_lookup_check`: Selector to toggle the lookup check.
#[derive(Debug, Clone)]
pub struct RangeCheckConfig<const N_BYTES: usize> {
    pub value: Column<Advice>,
    pub decomposed_value: Column<Advice>,
    pub running_sum: Column<Advice>,
    pub range: Column<Fixed>,
    pub toggle_running_sum_check: Selector,
    pub toggle_lookup_check: Selector,
}

/// Helper chip that verfiies that the value witnessed in a given cell lies within a given range defined by N_BYTES.
///
/// |     | value       | decomposed_value    | running_sum    | toggle_running_sum_check | toggle_lookup_check |
/// |-----|-------------|------               |------          | ------                   | ------              |
/// |  0  |  -          | -                   | 0x00           | 0                        | 0                   |
/// |  1  | 0x1f2f3f4f  | 0x1f                | 0x1f           | 1                        | 1                   |
/// |  2  |             | 0x2f                | 0x1f2f         | 1                        | 1                   |
/// |  3  |             | 0x3f                | 0x1f2f3f       | 1                        | 1                   |
/// |  4  |             | 0x4f                | 0x1f2f3f4f     | 1                        | 1                   |
///
/// The column decomposed_value contains the decomposition of `value` in #N_BYTES chunks, big-endian.
/// The column running_sum contains the running sum of the values in decomposed_value. In particular the running_sum in a particular row is the result of concatenating the prev running_sum with the current decomposed_value.
/// The contraints that are enforced are:
/// - (running_sum(prev) << 8) + decomposed_value(cur) = running_sum(cur) (enabled by toggle_running_sum_check)
/// - decomposed_value(cur) ∈ u8_lookup_table (enabled by toggle_lookup_check)
/// - value(1) == running_sum(4) (copy constraint applied here)
#[derive(Debug, Clone)]
pub struct RangeCheckChip<const N_BYTES: usize> {
    config: RangeCheckConfig<N_BYTES>,
}

impl<const N_BYTES: usize> RangeCheckChip<N_BYTES> {
    pub fn construct(config: RangeCheckConfig<N_BYTES>) -> Self {
        Self { config }
    }

    /// Configures the Overflow Chip
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        value: Column<Advice>,
        decomposed_value: Column<Advice>,
        running_sum: Column<Advice>,
        range: Column<Fixed>,
        toggle_running_sum_check: Selector,
        toggle_lookup_check: Selector,
    ) -> RangeCheckConfig<N_BYTES> {
        meta.create_gate(
            "equality check between running_sum_cur and running_sum_prev << 8 + running_sum_cur",
            |meta| {
                let running_sum_prev = meta.query_advice(running_sum, Rotation::prev());
                let decomposed_value_cur = meta.query_advice(decomposed_value, Rotation::cur());
                let running_sum_cur = meta.query_advice(running_sum, Rotation::cur());
                let s = meta.query_selector(toggle_running_sum_check);
                vec![
                    s * (running_sum_prev * Expression::Constant(Fp::from(1 << 8))
                        + decomposed_value_cur
                        - running_sum_cur),
                ]
            },
        );

        meta.annotate_lookup_any_column(range, || "LOOKUP_MAXBITS_RANGE");

        meta.lookup_any("range u8 check for decomposed value", |meta| {
            let decomposed_value_cell = meta.query_advice(decomposed_value, Rotation::cur());
            let range = meta.query_fixed(range, Rotation::cur());

            let enable_lookup = meta.query_selector(toggle_lookup_check);
            vec![(enable_lookup * decomposed_value_cell, range)]
        });

        RangeCheckConfig {
            value,
            decomposed_value,
            running_sum,
            range,
            toggle_running_sum_check,
            toggle_lookup_check,
        }
    }

    /// Assign the value to be checked to the chip. In particular, performs the following assignements
    /// - Assign an empty cell to running_sum(0)
    /// - Copy value to be performed range check on to value(1) enforcing a copy constraint
    /// - Assign the decomposition of value in #N_BYTES to decomposed_value(1..N_BYTES)
    /// - Assign the runnings sums to running_sum(1..N_BYTES - 1)
    /// - Copy value to be performed range check to running_sum(N_BYTES) enforcing a copy constraint
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign values to range check",
            |mut region| {
                // enable the selectors in offset [1, N_BYTES]
                for i in 1..=N_BYTES {
                    self.config
                        .toggle_running_sum_check
                        .enable(&mut region, i)?;
                    self.config.toggle_lookup_check.enable(&mut region, i)?;
                }

                // assign an empty cell to running_sum column at offset 0
                region.assign_advice(
                    || "inital running sum starts at 0",
                    self.config.running_sum,
                    0,
                    || Value::known(Fp::zero()),
                )?;

                // copy value to value column at offset 1
                value.copy_advice(|| "assign value", &mut region, self.config.value, 1)?;

                let (bytes_vecs, running_sums_vecs): (Value<Vec<Fp>>, Value<Vec<Fp>>) = value
                    .value()
                    .copied()
                    .map(|x| {
                        let bytes = decompose_fp_to_bytes(x, N_BYTES);
                        let running_sums = running_sums_of_bytes(bytes.clone());

                        // transform Vec<u8> into Vec<Fp>
                        let bytes_fp: Vec<Fp> = bytes
                            .into_iter()
                            .map(|byte| Fp::from(byte as u64))
                            .collect();

                        // tranform Vec<BigUint> into Vec<Fp>
                        let running_sums_fp: Vec<Fp> = running_sums
                            .into_iter()
                            .map(|running_sum| big_uint_to_fp(&running_sum))
                            .collect();

                        (bytes_fp, running_sums_fp)
                    })
                    .unzip();

                // assign decomposed_value to decomposed_value column at offset [1, N_BYTES]
                // assign running sum to running_sum column at offset [1, N_BYTES]
                for i in 1..=N_BYTES {
                    region.assign_advice(
                        || "assign decomposed value",
                        self.config.decomposed_value,
                        i,
                        || bytes_vecs.clone().map(|bytes| bytes[i - 1]),
                    )?;

                    if i == N_BYTES {
                        value.copy_advice(
                            || "value cell should match last running sum",
                            &mut region,
                            self.config.running_sum,
                            i,
                        )?;
                    } else {
                        region.assign_advice(
                            || "assign running sum",
                            self.config.running_sum,
                            i,
                            || {
                                running_sums_vecs
                                    .clone()
                                    .map(|running_sums| running_sums[i - 1])
                            },
                        )?;
                    }
                }
                Ok(())
            },
        )
    }

    /// Loads the lookup table with values from `0` to `2^8 - 1`
    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        let range = 1 << (8 as usize);

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
