use crate::chips::overflow::utils::*;

use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use std::fmt::Debug;

#[derive(Debug, Clone)]
pub struct OverflowCheckConfig<const MAX_BITS: u8, const ACC_COLS: usize> {
    pub a: Column<Advice>,
    pub decomposed_values: [Column<Advice>; ACC_COLS],
    pub range: Column<Fixed>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct OverflowChip<const MAX_BITS: u8, const ACC_COLS: usize> {
    config: OverflowCheckConfig<MAX_BITS, ACC_COLS>,
}

impl<const MAX_BITS: u8, const ACC_COLS: usize> OverflowChip<MAX_BITS, ACC_COLS> {
    pub fn construct(config: OverflowCheckConfig<MAX_BITS, ACC_COLS>) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> OverflowCheckConfig<MAX_BITS, ACC_COLS> {
        let selector = meta.selector();
        let range = meta.fixed_column();
        let a = meta.advice_column();
        let decomposed_values = [(); ACC_COLS].map(|_| meta.advice_column());

        meta.enable_equality(a);

        meta.create_gate(
            "equality check between decomposed_value and value",
            |meta| {
                let s_doc = meta.query_selector(selector);

                let value = meta.query_advice(a, Rotation::cur());

                let decomposed_value_vec = (0..ACC_COLS)
                    .map(|i: usize| meta.query_advice(decomposed_values[i], Rotation::cur()))
                    .collect::<Vec<_>>();

                // multiplier by position of accumulator column
                // e.g. for ACC_COLS = 3, multiplier = [2^(2*MAX_BITS), 2^MAX_BITS, 1]
                let multiplier = |pos: usize| {
                    let mut shift_chunk = Fp::one();
                    for _ in 1..pos {
                        shift_chunk *= Fp::from(1 << MAX_BITS);
                    }
                    Expression::Constant(shift_chunk)
                };

                // We are performing an important calculation here to check for overflow in finite field numbers.
                // A single range table is utilized which applies `1 << 8` to decompose the columns for range checking.
                //
                // Consider the example where ACC_COLS = 3, the decomposed values would be represented as follows:
                //
                // |     | a_0 (value) | a_1  | a_2  | a_3  |
                // |-----|-------------|------|------|------|
                // |  x  | 0x1f2f3f    | 0x1f | 0x2f | 0x3f |
                //
                // Here, each column `a_n` represents a decomposed value.
                // So, decomposed_value_sum would be calculated as a_1 * 2^16 + a_2 * 2^8 + a_3 * 1.
                //
                // During the iteration process in fold, the following would be the values of `acc`:
                // iteration 0: acc = decomposed_value_vec[1] * ( 1 << 8 ) + decomposed_value_vec[2]
                // iteration 1: acc = decomposed_value_vec[0] * ( 1 << 16 ) + decomposed_value_vec[1] * ( 1 << 8 ) + decomposed_value_vec[2]
                let decomposed_value_sum = (0..=ACC_COLS - 2).fold(
                    // decomposed value at right-most advice columnis is least significant byte
                    decomposed_value_vec[ACC_COLS - 1].clone(),
                    |acc, i| {
                        let cursor = ACC_COLS - i;
                        acc + (decomposed_value_vec[i].clone() * multiplier(cursor))
                    },
                );

                vec![s_doc * (decomposed_value_sum - value)]
            },
        );

        meta.annotate_lookup_any_column(range, || "LOOKUP_MAXBITS_RANGE");

        decomposed_values[0..ACC_COLS].iter().for_each(|column| {
            meta.lookup_any("range check for MAXBITS", |meta| {
                let cell = meta.query_advice(*column, Rotation::cur());
                let range = meta.query_fixed(range, Rotation::cur());
                vec![(cell, range)]
            });
        });

        OverflowCheckConfig {
            a,
            decomposed_values,
            range,
            selector,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign decomposed values",
            |mut region| {
                // enable selector
                self.config.selector.enable(&mut region, 0)?;

                // Assign input value to the cell inside the region
                value.copy_advice(|| "assign value", &mut region, self.config.a, 0)?;

                // Just used helper function for decomposing. In other halo2 application used functions based on Field.
                let decomposed_values: Vec<Fp> = decompose_bigint_to_ubits(
                    &value_fp_to_big_uint(value.value().map(|x| x.to_owned())),
                    ACC_COLS,
                    MAX_BITS as usize,
                ) as Vec<Fp>;

                // Note that, decomposed result is little edian. So, we need to reverse it.
                for (idx, val) in decomposed_values.iter().rev().enumerate() {
                    let _cell = region.assign_advice(
                        || format!("assign decomposed[{}] col", idx),
                        self.config.decomposed_values[idx],
                        0,
                        || Value::known(*val),
                    )?;
                }

                Ok(())
            },
        )
    }

    pub fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        let range = 1 << (MAX_BITS as usize);

        layouter.assign_region(
            || format!("load range check table of {} bits", MAX_BITS),
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
