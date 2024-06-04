use std::marker::PhantomData;

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::Rotation,
};

use crate::{entry::Entry, utils::big_uint_to_fp};

use halo2_proofs::arithmetic::Field;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use plonkish_backend::frontend::halo2::CircuitExt;
use rand::RngCore;

use super::config::circuit_config::CircuitConfig;

#[derive(Clone, Default)]
pub struct SummaHyperplonk<const N_USERS: usize, CONFIG: CircuitConfig<N_USERS>> {
    pub entries: Vec<Entry>,
    pub grand_total: Fp,
    _marker: PhantomData<CONFIG>,
}

impl<const N_USERS: usize, CONFIG: CircuitConfig<N_USERS>> SummaHyperplonk<N_USERS, CONFIG> {
    pub fn init(user_entries: Vec<Entry>) -> Self {
        let mut grand_total = Fp::zero();
        for entry in user_entries.iter() {
            grand_total += big_uint_to_fp::<Fp>(entry.balance());
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
    pub fn init_invalid_grand_total(user_entries: Vec<Entry>) -> Self {
        use plonkish_backend::util::test::seeded_std_rng;

        let grand_total = Fp::random(seeded_std_rng());

        Self {
            entries: user_entries,
            grand_total,
            _marker: PhantomData,
        }
    }
}

impl<const N_USERS: usize, CONFIG: CircuitConfig<N_USERS>> Circuit<Fp>
    for SummaHyperplonk<N_USERS, CONFIG>
{
    type Config = CONFIG;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        unimplemented!()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        meta.set_minimum_degree(4);

        let username = meta.advice_column();

        let balance = meta.advice_column();
        meta.enable_equality(balance);

        meta.create_gate("Balance sumcheck gate", |meta| {
            vec![meta.query_advice(balance, Rotation::cur())]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        CONFIG::configure(meta, username, balance, instance)
    }

    fn synthesize(&self, config: Self::Config, layouter: impl Layouter<Fp>) -> Result<(), Error> {
        CONFIG::synthesize(&config, layouter, &self.entries, &self.grand_total)
    }
}

impl<const N_USERS: usize, CONFIG: CircuitConfig<N_USERS>> CircuitExt<Fp>
    for SummaHyperplonk<N_USERS, CONFIG>
{
    fn rand(_: usize, _: impl RngCore) -> Self {
        unimplemented!()
    }

    fn instances(&self) -> Vec<Vec<Fp>> {
        // The 1st element is zero because the last decomposition of each range check chip should be zero
        vec![vec![Fp::ZERO, self.grand_total.neg()]]
    }
}
