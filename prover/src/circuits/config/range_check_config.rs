use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Instance},
};

use crate::chips::range::range_check::{RangeCheckChipConfig, RangeCheckU64Chip};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

use super::circuit_config::CircuitConfig;

/// Configuration that performs range checks.
///
/// # Type Parameters
///
/// * `N_USERS`: The number of users for which the solvency is verified.
///
/// # Fields
///
/// * `username`: Advice column used to store the usernames of the users
/// * `balances`: Advice columns used to store the balances of the users
/// * `range_check_configs`: Range check chip configurations
/// * `range_u16`: Fixed column used to store the lookup table
/// * `instance`: Instance column used to constrain the last balance decomposition
#[derive(Clone)]
pub struct RangeCheckConfig<const N_USERS: usize> {
    username: Column<Advice>,
    balance: Column<Advice>,
    range_check_config: RangeCheckChipConfig,
    range_u16: Column<Fixed>,
    instance: Column<Instance>,
}

impl<const N_USERS: usize> CircuitConfig<N_USERS> for RangeCheckConfig<N_USERS> {
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        username: Column<Advice>,
        balance: Column<Advice>,
        instance: Column<Instance>,
    ) -> Self {
        let range_u16 = meta.fixed_column();

        meta.enable_constant(range_u16);

        meta.annotate_lookup_any_column(range_u16, || "LOOKUP_MAXBITS_RANGE");

        let range_check_selector = meta.complex_selector();

        let z = balance;
        // Create 4 advice columns for each range check chip
        let zs = [(); 4].map(|_| meta.advice_column());

        for column in &zs {
            meta.enable_equality(*column);
        }

        let range_check_config =
            RangeCheckU64Chip::configure(meta, z, zs, range_u16, range_check_selector);

        Self {
            username,
            balance,
            range_check_config,
            range_u16,
            instance,
        }
    }

    fn get_username(&self) -> Column<Advice> {
        self.username
    }

    fn get_balance(&self) -> Column<Advice> {
        self.balance
    }

    fn get_instance(&self) -> Column<Instance> {
        self.instance
    }

    fn initialize_range_check_chip(&self) -> Vec<RangeCheckU64Chip> {
        vec![RangeCheckU64Chip::construct(self.range_check_config)]
    }

    fn load_lookup_table(&self, mut layouter: impl Layouter<Fp>) -> Result<(), Error> {
        // Load lookup table for range check u64 chip
        let range = 1 << 16;

        layouter.assign_region(
            || "load range check table of 16 bits".to_string(),
            |mut region| {
                for i in 0..range {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        self.range_u16,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }

    /// Constrains the last decompositions of each balance to a zero value (necessary for range checks)
    fn constrain_decompositions(
        &self,
        last_decomposition: halo2_proofs::circuit::AssignedCell<Fp, Fp>,
        layouter: &mut impl Layouter<Fp>,
    ) -> Result<(), Error> {
        layouter.constrain_instance(last_decomposition.cell(), self.instance, 0)?;
        Ok(())
    }
}
