use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Instance},
};

use crate::{entry::Entry, utils::big_uint_to_fp};

use crate::chips::range::range_check::RangeCheckU64Chip;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

/// The abstract configuration of the circuit.
/// The default implementation assigns the entries and grand total to the circuit, and constrains
/// grand total to the instance values.
///
/// The specific implementations have to provide the range check logic.
pub trait CircuitConfig<const N_USERS: usize>: Clone {
    /// Configures the circuit
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        username: Column<Advice>,
        balance: Column<Advice>,
        instance: Column<Instance>,
    ) -> Self;

    fn get_username(&self) -> Column<Advice>;

    fn get_balance(&self) -> Column<Advice>;

    fn get_instance(&self) -> Column<Instance>;

    /// Assigns the entries to the circuit, constrains the grand total to the instance values.
    fn synthesize(
        &self,
        mut layouter: impl Layouter<Fp>,
        entries: &[Entry],
        grand_total: &Fp,
    ) -> Result<(), Error> {
        // Initiate the range check chips
        let range_check_chip = self.initialize_range_check_chip();

        for (i, entry) in entries.iter().enumerate() {
            let last_decomposition = layouter.assign_region(
                || format!("assign entry {} to the table", i),
                |mut region| {
                    region.assign_advice(
                        || "username",
                        self.get_username(),
                        0,
                        || Value::known(big_uint_to_fp::<Fp>(entry.username_as_big_uint())),
                    )?;

                    let mut zs = Vec::with_capacity(4);

                    // The range check chip is empty when perform with "no_range_check_config"
                    if range_check_chip.is_empty() {
                        let zero_balance = region.assign_advice(
                            || "balance",
                            self.get_balance(),
                            0,
                            || Value::known(Fp::zero()),
                        )?;

                        Ok(zero_balance)
                    } else {
                        let assigned_balance = region.assign_advice(
                            || "balance",
                            self.get_balance(),
                            0,
                            || Value::known(big_uint_to_fp(entry.balance())),
                        )?;
                        range_check_chip[0].assign(&mut region, &mut zs, &assigned_balance)?;
                        Ok(zs[3].clone())
                    }
                },
            )?;

            self.constrain_decompositions(last_decomposition, &mut layouter)?;
        }

        let assigned_total = layouter.assign_region(
            || "assign total".to_string(),
            |mut region| {
                let balance_total = region.assign_advice(
                    || "total balance",
                    self.get_balance(),
                    0,
                    || Value::known(grand_total.neg()),
                )?;

                Ok(balance_total)
            },
        )?;

        layouter.constrain_instance(assigned_total.cell(), self.get_instance(), 1)?;

        self.load_lookup_table(layouter)?;

        Ok(())
    }

    /// Initializes the range check chips
    fn initialize_range_check_chip(&self) -> Vec<RangeCheckU64Chip>;

    /// Loads the lookup table
    fn load_lookup_table(&self, layouter: impl Layouter<Fp>) -> Result<(), Error>;

    /// Constrains the last decompositions of the balances to be zero
    fn constrain_decompositions(
        &self,
        last_decomposition: halo2_proofs::circuit::AssignedCell<Fp, Fp>,
        layouter: &mut impl Layouter<Fp>,
    ) -> Result<(), Error>;
}
