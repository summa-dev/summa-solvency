use crate::chips::overflow::utils::{decompose_bigint_to_ubits, value_f_to_big_uint};

use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
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
        Self {
            config,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
    ) -> OverflowCheckConfig<MAX_BITS, ACC_COLS> {
        let selector = meta.selector();
        let range = meta.fixed_column();
        let a = meta.advice_column();
        let decomposed_values = [(); ACC_COLS].map(|_| meta.advice_column());

        meta.create_gate("equality check between decomposed value and value", |meta| {
            let s_doc = meta.query_selector(selector);

            let value = meta.query_advice(a, Rotation::cur());

            let decomposed_value_vec = (0..ACC_COLS)
                .map(|i: usize| meta.query_advice(decomposed_values[i], Rotation::cur()))
                .collect::<Vec<_>>();

            let decomposed_value_sum =
                (0..=ACC_COLS - 2).fold(decomposed_value_vec[ACC_COLS - 1].clone(), |acc, i| {
                    acc + (decomposed_value_vec[i].clone()
                        * Expression::Constant(Fp::from(
                            1 << (MAX_BITS as usize * ((ACC_COLS - 1) - i)),
                        )))
                });

            vec![s_doc.clone() * (decomposed_value_sum - value)]
        });

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
        update_value: Value<Fp>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign decomposed values",
            |mut region| {
                // enable selector
                self.config.selector.enable(&mut region, 0)?;

                // Assign input value to the cell inside the region
                region.assign_advice(|| "assign value", self.config.a, 0, || update_value)?;

                // Just used helper function for decomposing. In other halo2 application used functions based on Field.
                let decomposed_values = decompose_bigint_to_ubits(
                    &value_f_to_big_uint(update_value),
                    MAX_BITS as usize,
                    ACC_COLS,
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
