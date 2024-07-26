pub mod summa_hyperplonk {

    use crate::chips::range::range_check::{RangeCheckU64Chip, RangeCheckU64Config};
    use crate::entry::Entry;
    use crate::utils::big_uint_to_fp;
    use halo2_proofs::arithmetic::Field;
    use halo2_proofs::halo2curves::bn256::Fr as Fp;
    use halo2_proofs::plonk::{Expression, Selector};
    use halo2_proofs::poly::Rotation;
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner, Value},
        plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
    };
    use num_bigint::BigUint;
    use plonkish_backend::frontend::halo2::CircuitExt;
    use rand::RngCore;

    #[derive(Clone)]
    pub struct SummaConfig<const N_CURRENCIES: usize, const N_USERS: usize> {
        username: Column<Advice>,
        balances: [Column<Advice>; N_CURRENCIES],
        running_sums: [Column<Advice>; N_CURRENCIES],
        range_check_configs: [RangeCheckU64Config; N_CURRENCIES],
        range_u16: Column<Fixed>,
        instance: Column<Instance>,
        selector: Selector,
    }

    impl<const N_CURRENCIES: usize, const N_USERS: usize> SummaConfig<N_CURRENCIES, N_USERS> {
        fn configure(meta: &mut ConstraintSystem<Fp>, running_sum_selector: &Selector) -> Self {
            let username = meta.advice_column();

            let balances = [(); N_CURRENCIES].map(|_| meta.advice_column());
            let running_sums = [(); N_CURRENCIES].map(|_| meta.advice_column());

            for column in &running_sums {
                meta.enable_equality(*column);
            }

            let range_u16 = meta.fixed_column();

            meta.enable_constant(range_u16);

            meta.annotate_lookup_any_column(range_u16, || "LOOKUP_MAXBITS_RANGE");

            // Create an empty array of range check configs
            let mut range_check_configs = Vec::with_capacity(N_CURRENCIES);

            let instance = meta.instance_column();
            meta.enable_equality(instance);

            for item in balances.iter().take(N_CURRENCIES) {
                let z = *item;
                // Create 4 advice columns for each range check chip
                let zs = [(); 4].map(|_| meta.advice_column());

                for column in &zs {
                    meta.enable_equality(*column);
                }

                let range_check_config = RangeCheckU64Chip::configure(meta, z, zs, range_u16);

                range_check_configs.push(range_check_config);
            }

            meta.create_gate("Running sum gate", |meta| {
                let mut running_sum_constraint = vec![];
                let s = meta.query_selector(*running_sum_selector);
                for j in 0..N_CURRENCIES {
                    let prev_running_sum = meta.query_advice(running_sums[j], Rotation::prev());
                    let curr_running_sum = meta.query_advice(running_sums[j], Rotation::cur());
                    let curr_balance = meta.query_advice(balances[j], Rotation::cur());
                    running_sum_constraint.push(
                        s.clone()
                            * (curr_running_sum.clone() - prev_running_sum - curr_balance.clone())
                            + (Expression::Constant(Fp::ONE) - s.clone())
                                * (curr_running_sum - curr_balance),
                    )
                }
                running_sum_constraint
            });

            Self {
                username,
                balances,
                running_sums,
                range_check_configs: range_check_configs.try_into().unwrap(),
                range_u16,
                instance,
                selector: *running_sum_selector,
            }
        }
    }

    #[derive(Clone, Default)]
    pub struct SummaHyperplonk<const N_USERS: usize, const N_CURRENCIES: usize> {
        pub entries: Vec<Entry<N_CURRENCIES>>,
        pub grand_total: Vec<BigUint>,
    }

    impl<const N_USERS: usize, const N_CURRENCIES: usize> SummaHyperplonk<N_USERS, N_CURRENCIES> {
        pub fn init(user_entries: Vec<Entry<N_CURRENCIES>>) -> Self {
            let mut grand_total = vec![BigUint::from(0u64); N_CURRENCIES];
            for entry in user_entries.iter() {
                for (i, balance) in entry.balances().iter().enumerate() {
                    grand_total[i] += balance;
                }
            }

            Self {
                entries: user_entries,
                grand_total,
            }
        }

        pub fn init_empty() -> Self {
            Self {
                entries: vec![Entry::init_empty(); N_USERS],
                grand_total: vec![BigUint::from(0u64); N_CURRENCIES],
            }
        }
    }

    impl<const N_USERS: usize, const N_CURRENCIES: usize> Circuit<Fp>
        for SummaHyperplonk<N_USERS, N_CURRENCIES>
    {
        type Config = SummaConfig<N_CURRENCIES, N_USERS>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            unimplemented!()
        }

        fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
            meta.set_minimum_degree(4);
            let running_sum_selector = &meta.complex_selector();
            SummaConfig::configure(meta, running_sum_selector)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<Fp>,
        ) -> Result<(), Error> {
            // Assign entries
            let (assigned_balances, last_running_sums) = layouter
                .assign_region(
                    || "assign user entries",
                    |mut region| {
                        // create a bidimensional vector to store the assigned balances. The first dimension is N_USERS, the second dimension is N_CURRENCIES
                        let mut assigned_balances = vec![];

                        let mut running_sum_values = vec![vec![]];
                        let mut last_assigned_running_sums = vec![];

                        for i in 0..N_USERS {
                            running_sum_values.push(vec![]);

                            region.assign_advice(
                                || format!("username {}", i),
                                config.username,
                                i,
                                || {
                                    Value::known(big_uint_to_fp::<Fp>(
                                        self.entries[i].username_as_big_uint(),
                                    ))
                                },
                            )?;

                            let mut assigned_balances_row = vec![];

                            for (j, balance) in self.entries[i].balances().iter().enumerate() {
                                let balance_value: Value<Fp> =
                                    Value::known(big_uint_to_fp(balance));

                                let assigned_balance = region.assign_advice(
                                    || format!("balance {}", j),
                                    config.balances[j],
                                    i,
                                    || balance_value,
                                )?;

                                assigned_balances_row.push(assigned_balance);

                                let prev_running_sum_value = if i == 0 {
                                    Value::known(Fp::ZERO)
                                } else {
                                    running_sum_values[i - 1][j]
                                };

                                running_sum_values[i].push(prev_running_sum_value + balance_value);

                                let assigned_running_sum = region.assign_advice(
                                    || format!("running sum {}", j),
                                    config.running_sums[j],
                                    i,
                                    || running_sum_values[i][j],
                                )?;

                                if i == N_USERS - 1 {
                                    last_assigned_running_sums.push(assigned_running_sum);
                                }
                            }

                            if i > 0 {
                                config.selector.enable(&mut region, i)?;
                            }

                            assigned_balances.push(assigned_balances_row);
                        }

                        Ok((assigned_balances, last_assigned_running_sums))
                    },
                )
                .unwrap();

            // Initialize the range check chips
            let range_check_chips = config
                .range_check_configs
                .iter()
                .map(|config| RangeCheckU64Chip::construct(*config))
                .collect::<Vec<_>>();

            // Load lookup table for range check u64 chip
            let range = 1 << 16;

            layouter.assign_region(
                || "load range check table of 16 bits".to_string(),
                |mut region| {
                    for i in 0..range {
                        region.assign_fixed(
                            || "assign cell in fixed column",
                            config.range_u16,
                            i,
                            || Value::known(Fp::from(i as u64)),
                        )?;
                    }
                    Ok(())
                },
            )?;

            // Perform range check on the assigned balances
            for (i, user_balances) in assigned_balances.iter().enumerate().take(N_USERS) {
                for (j, balance) in user_balances.iter().enumerate() {
                    let mut zs = Vec::with_capacity(4);

                    layouter.assign_region(
                        || format!("Perform range check on balance {} of user {}", j, i),
                        |mut region| {
                            range_check_chips[j].assign(&mut region, &mut zs, balance)?;
                            Ok(())
                        },
                    )?;

                    layouter.constrain_instance(zs[3].cell(), config.instance, 0)?;
                }
            }

            for (i, last_running_sum) in last_running_sums.iter().enumerate().take(N_CURRENCIES) {
                layouter.constrain_instance(last_running_sum.cell(), config.instance, 1 + i)?;
            }

            Ok(())
        }
    }

    impl<const N_USERS: usize, const N_CURRENCIES: usize> CircuitExt<Fp>
        for SummaHyperplonk<N_USERS, N_CURRENCIES>
    {
        fn rand(_: usize, _: impl RngCore) -> Self {
            unimplemented!()
        }

        fn instances(&self) -> Vec<Vec<Fp>> {
            // The last decomposition of each range check chip should be zero
            let mut instances = vec![Fp::ZERO];
            instances.extend(self.grand_total.iter().map(big_uint_to_fp::<Fp>));
            vec![instances]
        }
    }
}
