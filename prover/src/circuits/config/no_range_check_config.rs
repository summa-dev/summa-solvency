use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance},
};

use crate::chips::range::range_check::RangeCheckU64Chip;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

use super::circuit_config::CircuitConfig;

/// Configuration that does not perform range checks. Warning: not for use in production!
/// The circuit without range checks can use a lower K value (9+) than the full circuit (convenient for prototyping and testing).
///
/// # Type Parameters
///
/// * `N_USERS`: The number of users for which the solvency is verified.
///
/// # Fields
///
/// * `username`: Advice column used to store the usernames of the users
/// * `balance`: Advice columns used to store the balance of the users
#[derive(Clone)]
pub struct NoRangeCheckConfig<const N_USERS: usize> {
    username: Column<Advice>,
    balance: Column<Advice>,
    instance: Column<Instance>,
}

impl<const N_USERS: usize> CircuitConfig<N_USERS> for NoRangeCheckConfig<N_USERS> {
    fn configure(
        _: &mut ConstraintSystem<Fp>,
        username: Column<Advice>,
        balance: Column<Advice>,
        instance: Column<Instance>,
    ) -> NoRangeCheckConfig<N_USERS> {
        Self {
            username,
            balance,
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

    // The following methods are not implemented for NoRangeCheckConfig

    fn initialize_range_check_chip(&self) -> Vec<RangeCheckU64Chip> {
        vec![]
    }

    fn load_lookup_table(&self, _: impl Layouter<Fp>) -> Result<(), Error> {
        Ok(())
    }

    fn constrain_decompositions(
        &self,
        _: halo2_proofs::circuit::AssignedCell<Fp, Fp>,
        _: &mut impl Layouter<Fp>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
