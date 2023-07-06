#[cfg(test)]
mod test {
    use crate::chips::less_than::less_than_vertical::{
        LtVerticalChip, LtVerticalConfig, LtVerticalInstruction,
    };
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
