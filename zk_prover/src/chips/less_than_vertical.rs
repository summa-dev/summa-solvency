//! This is a 'vertical' implementation of LTChip
//! It reduces the number of advice columns present in the original 'horizontal approach' available in the zkevm gadgets.

use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    halo2curves::{bn256::Fr as Fp, ff::PrimeField},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
    poly::Rotation,
};

use gadgets::{
    bool_check,
    util::{expr_from_bytes, pow_of_two},
};

/// Instruction that the Lt vertical chip needs to implement.
pub trait LtVerticalInstruction {
    /// Assign the lhs and rhs witnesses to the Lt chip's region.
    fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        lhs: Value<Fp>,
        rhs: Value<Fp>,
    ) -> Result<(), Error>;

    /// Load the u8 lookup table.
    fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error>;
}

/// Config for the LtVertical chip.
#[derive(Clone, Copy, Debug)]
pub struct LtVerticalConfig<const N_BYTES: usize> {
    /// Denotes the lt outcome. If lhs < rhs then lt == 1, otherwise lt == 0.
    pub lt: Column<Advice>,
    /// Denotes the bytes representation of the difference between lhs and rhs.
    pub diff: Column<Advice>,
    /// Denotes the range within which each byte should lie.
    pub u8: Column<Fixed>,
    /// Denotes the range within which both lhs and rhs lie.
    pub range: Fp,
    /// Denotes the selector used to enable the lookup check
    pub lookup_enable: Selector,
}

impl<const N_BYTES: usize> LtVerticalConfig<N_BYTES> {
    /// Returns an expression that denotes whether lhs < rhs, or not.
    pub fn is_lt(&self, meta: &mut VirtualCells<Fp>, rotation: Option<Rotation>) -> Expression<Fp> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }
}

/// Chip that compares lhs < rhs. It performs the following constraints:
///
/// * `lhs - rhs - diff_bytes + lt * range = 0`. When q_enable is 1, this constraint is enforced.
/// * `lt * (lt - 1) = 0`, i.e. lt is either 0 or 1. When q_enable is 1, this constraint is enforced.
/// * `diff(cur)` ∈ to `u8` lookup table. Namely `decomposed_value` should be in the `MAX_BITS` range. When q_enable is 1, this constraint is enforced.

#[derive(Clone, Debug)]
pub struct LtVerticalChip<const N_BYTES: usize> {
    config: LtVerticalConfig<N_BYTES>,
}

impl<const N_BYTES: usize> LtVerticalChip<N_BYTES> {
    /// Configures the LtVertical chip.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, Fp>) -> Expression<Fp>,
        lhs: impl FnOnce(&mut VirtualCells<Fp>) -> Expression<Fp>,
        rhs: impl FnOnce(&mut VirtualCells<Fp>) -> Expression<Fp>,
        lt: Column<Advice>,
        diff: Column<Advice>,
        u8: Column<Fixed>,
        lookup_enable: Selector,
    ) -> LtVerticalConfig<N_BYTES> {
        let range = pow_of_two(N_BYTES * 8);

        meta.create_gate("lt gate", |meta| {
            let q_enable = q_enable(meta);
            let lt = meta.query_advice(lt, Rotation::cur());

            let diff_bytes: Vec<Expression<Fp>> = (0..N_BYTES)
                .map(|i| meta.query_advice(diff, Rotation(i as i32)))
                .collect();

            let check_a =
                lhs(meta) - rhs(meta) - expr_from_bytes(&diff_bytes) + (lt.clone() * range);

            let check_b = bool_check(lt);

            [check_a, check_b]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        meta.annotate_lookup_any_column(u8, || "LOOKUP_u8");

        meta.lookup_any("range check for u8", |meta| {
            let u8_cell = meta.query_advice(diff, Rotation::cur());
            let u8_range = meta.query_fixed(u8, Rotation::cur());
            let lookup_enable = meta.query_selector(lookup_enable);
            vec![(lookup_enable * u8_cell, u8_range)]
        });

        LtVerticalConfig {
            lt,
            diff,
            range,
            u8,
            lookup_enable,
        }
    }

    /// Constructs a Lt chip given a config.
    pub fn construct(config: LtVerticalConfig<N_BYTES>) -> LtVerticalChip<N_BYTES> {
        LtVerticalChip { config }
    }
}

impl<const N_BYTES: usize> LtVerticalInstruction for LtVerticalChip<N_BYTES> {
    /// From lhs and rhs values, assigns `lt` and `diff_bytes` to the region.
    fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        lhs: Value<Fp>,
        rhs: Value<Fp>,
    ) -> Result<(), Error> {
        let config = self.config();

        let lt = lhs.zip(rhs).map(|(lhs, rhs)| lhs < rhs);

        region.assign_advice(
            || "lt chip: lt",
            config.lt,
            offset,
            || lt.map(|lt| Fp::from(lt as u64)),
        )?;

        let diff_bytes = lhs.zip(rhs).map(|(lhs, rhs)| {
            let mut diff = lhs - rhs;
            let lt = lhs < rhs;
            if lt {
                diff += config.range;
            } else {
                diff += Fp::zero();
            }
            diff.to_repr()
        });

        for idx in 0..N_BYTES {
            region.assign_advice(
                || format!("lt chip: diff byte {}", idx),
                config.diff,
                offset + idx,
                || diff_bytes.as_ref().map(|bytes| Fp::from(bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }

    /// Loads the lookup table for `u8` range check.
    fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        const RANGE: usize = 256;

        layouter.assign_region(
            || "load u8 range check table",
            |mut region| {
                for i in 0..RANGE {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        self.config.u8,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

impl<const N_BYTES: usize> Chip<Fp> for LtVerticalChip<N_BYTES> {
    type Config = LtVerticalConfig<N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::bn256::Fr as Fp,
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Selector},
        poly::Rotation,
    };

    macro_rules! try_test_circuit {
        ($values:expr, $checks:expr, $result:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = 9;
            let circuit = TestCircuit {
                values: Some($values),
                checks: Some($checks),
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), $result);
        }};
    }

    macro_rules! try_test_circuit_error {
        ($values:expr, $checks:expr) => {{
            // let k = usize::BITS - $values.len().leading_zeros();

            // TODO: remove zk blinding factors in halo2 to restore the
            // correct k (without the extra + 2).
            let k = 9;
            let circuit = TestCircuit {
                values: Some($values),
                checks: Some($checks),
            };
            let prover = MockProver::<Fp>::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }};
    }

    const N_BYTES: usize = 31;

    #[test]
    fn row_diff_is_lt() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig {
            q_enable: Selector,
            value: Column<Advice>,
            check: Column<Advice>,
            lt: LtVerticalConfig<N_BYTES>,
        }

        #[derive(Default)]
        struct TestCircuit {
            values: Option<Vec<u64>>,
            // checks[i] = lt(values[i + 1], values[i])
            checks: Option<Vec<bool>>,
        }

        impl Circuit<Fp> for TestCircuit {
            type Config = TestCircuitConfig;
            type FloorPlanner = SimpleFloorPlanner;
            // type Params = () - optional, requires the circuit-params feature

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let q_enable = meta.selector();
                let value = meta.advice_column();
                let check = meta.advice_column();
                let lt = meta.advice_column();
                let diff = meta.advice_column();
                let u8 = meta.fixed_column();
                let lookup_enable = meta.complex_selector();

                let lt = LtVerticalChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| meta.query_advice(value, Rotation::prev()),
                    |meta| meta.query_advice(value, Rotation::cur()),
                    lt,
                    diff,
                    u8,
                    lookup_enable,
                );

                let config = Self::Config {
                    q_enable,
                    value,
                    check,
                    lt,
                };

                meta.create_gate("check is_lt between adjacent rows", |meta| {
                    let q_enable = meta.query_selector(q_enable);

                    // This verifies lt(value::cur, value::next) is calculated correctly
                    let check = meta.query_advice(config.check, Rotation::cur());

                    vec![q_enable * (config.lt.is_lt(meta, None) - check)]
                });

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let chip = LtVerticalChip::construct(config.lt);

                let values: Vec<_> = self
                    .values
                    .as_ref()
                    .map(|values| values.iter().map(|value| Fp::from(*value)).collect())
                    .ok_or(Error::Synthesis)?;
                let checks = self.checks.as_ref().ok_or(Error::Synthesis)?;
                let (first_value, values) = values.split_at(1);
                let first_value = first_value[0];

                chip.load(&mut layouter)?;

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        region.assign_advice(
                            || "first row value",
                            config.value,
                            0,
                            || Value::known(first_value),
                        )?;

                        let mut value_prev = first_value;
                        for (idx, (value, check)) in values.iter().zip(checks).enumerate() {
                            config.q_enable.enable(&mut region, idx + 1)?;
                            region.assign_advice(
                                || "check",
                                config.check,
                                idx + 1,
                                || Value::known(Fp::from(*check as u64)),
                            )?;
                            region.assign_advice(
                                || "value",
                                config.value,
                                idx + 1,
                                || Value::known(*value),
                            )?;
                            chip.assign(
                                &mut region,
                                idx + 1,
                                Value::known(value_prev),
                                Value::known(*value),
                            )?;

                            value_prev = *value;
                        }

                        for i in 0..N_BYTES {
                            config.lt.lookup_enable.enable(&mut region, i + 1)?;
                        }

                        Ok(())
                    },
                )
            }
        }

        try_test_circuit!(vec![1, 2], vec![true], Ok(()));
        try_test_circuit!(vec![2, 3], vec![true], Ok(()));
        try_test_circuit!(vec![3, 4], vec![true], Ok(()));
        try_test_circuit!(vec![4, 5], vec![true], Ok(()));
        try_test_circuit!(vec![1, 2], vec![true], Ok(()));
        try_test_circuit!(vec![2, 1], vec![false], Ok(()));
        try_test_circuit!(vec![1, 3], vec![true], Ok(()));
        try_test_circuit!(vec![3, 2], vec![false], Ok(()));

        // // // error
        try_test_circuit_error!(vec![5, 4], vec![true]);
        try_test_circuit_error!(vec![4, 3], vec![true]);
        try_test_circuit_error!(vec![3, 2], vec![true]);
        try_test_circuit_error!(vec![2, 1], vec![true]);
        try_test_circuit_error!(vec![1, 2], vec![false]);
        try_test_circuit_error!(vec![2, 1], vec![true]);
        try_test_circuit_error!(vec![1, 3], vec![false]);
        try_test_circuit_error!(vec![3, 2], vec![true]);
    }

    #[test]
    fn column_diff_is_lt() {
        #[derive(Clone, Debug)]
        struct TestCircuitConfig {
            q_enable: Selector,
            value_a: Column<Advice>,
            value_b: Column<Advice>,
            check: Column<Advice>,
            lt: LtVerticalConfig<N_BYTES>,
        }

        #[derive(Default)]
        struct TestCircuit {
            values: Option<Vec<(u64, u64)>>,
            // checks[i] = lt(values[i].0 - values[i].1)
            checks: Option<Vec<bool>>,
        }

        impl Circuit<Fp> for TestCircuit {
            type Config = TestCircuitConfig;
            type FloorPlanner = SimpleFloorPlanner;
            // type Params = ();

            fn without_witnesses(&self) -> Self {
                Self::default()
            }

            fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
                let q_enable = meta.complex_selector();
                let (value_a, value_b) = (meta.advice_column(), meta.advice_column());
                let check = meta.advice_column();
                let lt = meta.advice_column();
                let diff = meta.advice_column();
                let u8 = meta.fixed_column();
                let lookup_enable = meta.complex_selector();

                let lt = LtVerticalChip::configure(
                    meta,
                    |meta| meta.query_selector(q_enable),
                    |meta| meta.query_advice(value_a, Rotation::cur()),
                    |meta| meta.query_advice(value_b, Rotation::cur()),
                    lt,
                    diff,
                    u8,
                    lookup_enable,
                );

                let config = Self::Config {
                    q_enable,
                    value_a,
                    value_b,
                    check,
                    lt,
                };

                meta.create_gate("check is_lt between columns in the same row", |meta| {
                    let q_enable = meta.query_selector(q_enable);

                    // This verifies lt(lhs, rhs) is calculated correctly
                    let check = meta.query_advice(config.check, Rotation::cur());

                    vec![q_enable * (config.lt.is_lt(meta, None) - check)]
                });

                config
            }

            fn synthesize(
                &self,
                config: Self::Config,
                mut layouter: impl Layouter<Fp>,
            ) -> Result<(), Error> {
                let chip = LtVerticalChip::construct(config.lt);

                let values: Vec<_> = self
                    .values
                    .as_ref()
                    .map(|values| {
                        values
                            .iter()
                            .map(|(value_a, value_b)| (Fp::from(*value_a), Fp::from(*value_b)))
                            .collect()
                    })
                    .ok_or(Error::Synthesis)?;
                let checks = self.checks.as_ref().ok_or(Error::Synthesis)?;

                chip.load(&mut layouter)?;

                layouter.assign_region(
                    || "witness",
                    |mut region| {
                        for (idx, ((value_a, value_b), check)) in
                            values.iter().zip(checks).enumerate()
                        {
                            config.q_enable.enable(&mut region, idx + 1)?;
                            region.assign_advice(
                                || "check",
                                config.check,
                                idx + 1,
                                || Value::known(Fp::from(*check as u64)),
                            )?;
                            region.assign_advice(
                                || "value_a",
                                config.value_a,
                                idx + 1,
                                || Value::known(*value_a),
                            )?;
                            region.assign_advice(
                                || "value_b",
                                config.value_b,
                                idx + 1,
                                || Value::known(*value_b),
                            )?;
                            chip.assign(
                                &mut region,
                                idx + 1,
                                Value::known(*value_a),
                                Value::known(*value_b),
                            )?;

                            for i in 0..N_BYTES {
                                config.lt.lookup_enable.enable(&mut region, i + 1)?;
                            }
                        }

                        Ok(())
                    },
                )
            }
        }

        // ok
        try_test_circuit!(vec![(1, 2)], vec![true], Ok(()));
        try_test_circuit!(vec![(4, 4)], vec![false], Ok(()));
        try_test_circuit!(vec![(5, 5)], vec![false], Ok(()));
        try_test_circuit!(vec![(14124, 14124)], vec![false], Ok(()));
        try_test_circuit!(vec![(383168732, 383168731)], vec![false], Ok(()));
        try_test_circuit!(vec![(383168731, 383168732)], vec![true], Ok(()));

        // // error
        try_test_circuit_error!(vec![(1, 2)], vec![false]);
        try_test_circuit_error!(vec![(3, 4)], vec![false]);
        try_test_circuit_error!(vec![(5, 6)], vec![false]);
        try_test_circuit_error!(vec![(1, 1)], vec![true]);
        try_test_circuit_error!(vec![(3, 4)], vec![false]);
        try_test_circuit_error!(vec![(6, 6)], vec![true]);
    }
}
