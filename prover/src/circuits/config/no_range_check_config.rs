use halo2_proofs::{
    circuit::Layouter,
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
};

use crate::chips::range::range_check::RangeCheckU64Chip;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

use super::circuit_config::CircuitConfig;

/// Configuration that does not perform range checks. Warning: not for use in production!
/// The circuit without range checks can use a lower K value (9+) than the full circuit (convenient for prototyping and testing).
///
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of currencies for which the solvency is verified.
/// * `N_USERS`: The number of users for which the solvency is verified.
///
/// # Fields
///
/// * `username`: Advice column used to store the usernames of the users
/// * `concentrations`: Advice columns used to store the concentrations of the users
/// * `balances`: Advice columns used to store the balances of the users
/// * `instance`: Instance column used to constrain the last balance decomposition
#[derive(Clone)]
pub struct NoRangeCheckConfig<const N_CURRENCIES: usize, const N_USERS: usize> {
    username: Column<Advice>,
    concatenated_balance: Column<Advice>,
    balances: [Column<Advice>; N_CURRENCIES],
    instance: Column<Instance>,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> CircuitConfig<N_CURRENCIES, N_USERS>
    for NoRangeCheckConfig<N_CURRENCIES, N_USERS>
{
    fn configure(
        _: &mut ConstraintSystem<Fp>,
        username: Column<Advice>,
        concatenated_balance: Column<Advice>,
        _selector: Selector,
        balances: [Column<Advice>; N_CURRENCIES],
        instance: Column<Instance>,
    ) -> NoRangeCheckConfig<N_CURRENCIES, N_USERS> {
        Self {
            username,
            concatenated_balance,
            balances,
            instance,
        }
    }

    fn get_username(&self) -> Column<Advice> {
        self.username
    }

    fn get_concatenated_balance(&self) -> Column<Advice> {
        self.concatenated_balance
    }

    fn get_balances(&self) -> [Column<Advice>; N_CURRENCIES] {
        self.balances
    }

    fn get_instance(&self) -> Column<Instance> {
        self.instance
    }

    // The following methods are not implemented for NoRangeCheckConfig

    fn initialize_range_check_chips(&self) -> Vec<RangeCheckU64Chip> {
        vec![]
    }

    fn load_lookup_table(&self, _: impl Layouter<Fp>) -> Result<(), Error> {
        Ok(())
    }

    fn constrain_decompositions(
        &self,
        _: Vec<halo2_proofs::circuit::AssignedCell<Fp, Fp>>,
        _: &mut impl Layouter<Fp>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
