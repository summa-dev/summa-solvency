use halo2_proofs::{
    arithmetic::Field,
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::{bn256::Fr as Fp, ff::PrimeField},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
    poly::Rotation,
};
use plonkish_backend::frontend::halo2::CircuitExt;
use rand::RngCore;
use std::marker::PhantomData;

use super::config::circuit_config::CircuitConfig;
use crate::{
    entry::Entry,
    utils::{big_uint_to_fp, calculate_shift_bits},
};

#[derive(Clone, Default)]
pub struct SummaHyperplonk<
    const N_USERS: usize,
    const N_CURRENCIES: usize,
    CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
> {
    pub entries: Vec<Entry<N_USERS, N_CURRENCIES>>,
    pub concatenated_grand_total: Fp,
    _marker: PhantomData<CONFIG>,
}

impl<
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    > SummaHyperplonk<N_USERS, N_CURRENCIES, CONFIG>
{
    pub fn init(user_entries: Vec<Entry<N_USERS, N_CURRENCIES>>) -> Self {
        let mut concatenated_grand_total = Fp::ZERO;

        for entry in user_entries.iter() {
            concatenated_grand_total +=
                big_uint_to_fp::<Fp>(&entry.concatenated_balance().unwrap());
        }

        Self {
            entries: user_entries,
            concatenated_grand_total,
            _marker: PhantomData,
        }
    }

    /// Initialize the circuit with an invalid grand total
    /// (for testing purposes only).
    #[cfg(test)]
    pub fn init_invalid_grand_total(user_entries: Vec<Entry<N_USERS, N_CURRENCIES>>) -> Self {
        use plonkish_backend::util::test::seeded_std_rng;

        let concatenated_grand_total = Fp::random(seeded_std_rng());

        Self {
            entries: user_entries,
            concatenated_grand_total,
            _marker: PhantomData,
        }
    }
}

impl<
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    > Circuit<Fp> for SummaHyperplonk<N_USERS, N_CURRENCIES, CONFIG>
{
    type Config = CONFIG;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        meta.set_minimum_degree(4);

        let username = meta.advice_column();

        let concatenated_balance = meta.advice_column();
        meta.enable_equality(concatenated_balance);

        meta.create_gate("Concatenated balance sumcheck gate", |meta| {
            let current_balance = meta.query_advice(concatenated_balance, Rotation::cur());
            vec![current_balance.clone()]
        });

        let q_enable = meta.complex_selector();

        let balances = [(); N_CURRENCIES].map(|_| meta.advice_column());
        for column in &balances {
            meta.enable_equality(*column);
        }

        meta.create_gate("Concatenated balance validation check gate", |meta| {
            let s = meta.query_selector(q_enable);

            let concatenated_balance = meta.query_advice(concatenated_balance, Rotation::cur());

            // Right-most balance column is for the least significant balance in concatenated balance.
            let mut balances_expr = meta.query_advice(balances[N_CURRENCIES - 1], Rotation::cur());

            let shift_bits = calculate_shift_bits::<N_USERS, N_CURRENCIES>().unwrap();

            // The shift bits would not be exceed 93 bits
            let base_shift = Fp::from_u128(1u128 << shift_bits);

            let mut current_shift = Expression::Constant(base_shift);

            // The number of currencies is limited 1 or 3 because the range check chip logic.
            // In other words, more than 3 currencies would exceed the maximum bit count of 254, which is number of bits in Bn254.
            match N_CURRENCIES {
                1 => {
                    // No need to add any shift for the only balance
                    println!("For a better performance for single currency, check out V3c. More details at: https://github.com/summa-dev/summa-solvency/tree/v3c");
                },
                3 => {
                    for i in (0..N_CURRENCIES - 1).rev() {
                        let balance = meta.query_advice(balances[i], Rotation::cur());
                        let shifted_balance = balance * current_shift.clone();
                        balances_expr = balances_expr + shifted_balance;

                        if i != 0 {
                            current_shift = current_shift * Expression::Constant(base_shift);
                        }
                    }
                }
                _ => panic!(
                    "Unsupported number of currencies, Only 1 and 3 currencies are supported"
                ),
            }

            // Ensure that the whole expression equals to the concatenated_balance
            vec![s * (concatenated_balance - balances_expr)]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        CONFIG::configure(
            meta,
            username,
            concatenated_balance,
            q_enable,
            balances,
            instance,
        )
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        CONFIG::synthesize(
            &config,
            layouter,
            &self.entries,
            &self.concatenated_grand_total,
        )
    }
}

impl<
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    > CircuitExt<Fp> for SummaHyperplonk<N_USERS, N_CURRENCIES, CONFIG>
{
    fn rand(_: usize, _: impl RngCore) -> Self {
        unimplemented!()
    }

    fn instances(&self) -> Vec<Vec<Fp>> {
        // The 1st element is zero because the last decomposition of each range check chip should be zero
        vec![vec![Fp::ZERO, self.concatenated_grand_total.neg()]]
    }
}
