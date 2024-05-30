use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
    poly::Rotation,
};

use crate::{entry::Entry, utils::big_uint_to_fp};

use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use plonkish_backend::frontend::halo2::CircuitExt;
use rand::RngCore;

use super::config::circuit_config::CircuitConfig;

#[derive(Clone, Default)]
pub struct SummaHyperplonk<
    const N_USERS: usize,
    const N_CURRENCIES: usize,
    CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
> {
    pub entries: Vec<Entry<N_CURRENCIES>>,
    pub grand_total: Vec<Fp>,
    _marker: PhantomData<CONFIG>,
}

impl<
        const N_USERS: usize,
        const N_CURRENCIES: usize,
        CONFIG: CircuitConfig<N_CURRENCIES, N_USERS>,
    > SummaHyperplonk<N_USERS, N_CURRENCIES, CONFIG>
{
    pub fn init(user_entries: Vec<Entry<N_CURRENCIES>>) -> Self {
        let mut grand_total = vec![Fp::ZERO; N_CURRENCIES];
        for entry in user_entries.iter() {
            for (i, balance) in entry.balances().iter().enumerate() {
                grand_total[i] += big_uint_to_fp::<Fp>(balance);
            }
        }

        Self {
            entries: user_entries,
            grand_total,
            _marker: PhantomData,
        }
    }

    /// Initialize the circuit with an invalid grand total
    /// (for testing purposes only).
    #[cfg(test)]
    pub fn init_invalid_grand_total(user_entries: Vec<Entry<N_CURRENCIES>>) -> Self {
        use plonkish_backend::util::test::seeded_std_rng;

        let mut grand_total = vec![Fp::ZERO; N_CURRENCIES];
        for i in 0..N_CURRENCIES {
            grand_total[i] = Fp::random(seeded_std_rng());
        }

        Self {
            entries: user_entries,
            grand_total,
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

        let q_enable = meta.complex_selector();

        let balances = [(); N_CURRENCIES].map(|_| meta.advice_column());
        for column in &balances {
            meta.enable_equality(*column);
        }

        meta.create_gate("Concatenated balance sumcheck gate", |meta| {
            vec![meta.query_advice(concatenated_balance, Rotation::cur())]
        });

        meta.create_gate("Concatenated balance validation check gate", |meta| {
            let q_enable = meta.query_selector(q_enable);

            let concatenated_balance = meta.query_advice(concatenated_balance, Rotation::cur());
            let mut expr = Expression::Constant(Fp::zero()); // start with a zero expression if needed

            // Base shift value for 84 bits.
            let base_shift = Fp::from(1 << 63).mul(&Fp::from(1 << 21));

            // We will multiply this base_shift for each balance iteratively.
            let mut current_shift = Expression::Constant(Fp::one()); // Start with no shift for the first element.

            for (i, balance_col) in balances.iter().enumerate() {
                let balance = meta.query_advice(*balance_col, Rotation::cur());
                let shifted_balance = balance * current_shift.clone(); // Apply the current shift
                expr = expr + shifted_balance; // Add to the expression

                // Update the shift for the next iteration
                if i < balances.len() - 1 {
                    // Prevent updating shift unnecessarily on the last element
                    current_shift = current_shift * Expression::Constant(base_shift);
                }
            }

            // Ensure that the whole expression equals to the concatenated_balance
            vec![q_enable * (concatenated_balance - expr)]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        CONFIG::configure(meta, username, concatenated_balance, balances, instance)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        CONFIG::synthesize(&config, layouter, &self.entries, &self.grand_total)
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
        vec![vec![Fp::ZERO]
            .into_iter()
            .chain(self.grand_total.iter().map(|x| x.neg()))
            .collect::<Vec<Fp>>()]
    }
}
