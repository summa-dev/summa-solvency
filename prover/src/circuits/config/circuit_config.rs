use halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Instance, Selector},
};

use crate::{entry::Entry, utils::big_uint_to_fp};

use crate::chips::range::range_check::RangeCheckU64Chip;
use halo2_proofs::halo2curves::bn256::Fr as Fp;

/// The abstract configuration of the circuit.
/// The default implementation assigns the entries and grand total to the circuit, and constrains
/// grand total to the instance values.
///
/// The specific implementations have to provide the range check logic.
pub trait CircuitConfig<const N_CURRENCIES: usize, const N_USERS: usize>: Clone {
    /// Configures the circuit
    fn configure(
        meta: &mut ConstraintSystem<Fp>,
        username: Column<Advice>,
        concatenated_balance: Column<Advice>,
        selector: Selector,
        balances: [Column<Advice>; N_CURRENCIES],
        instance: Column<Instance>,
    ) -> Self;

    fn get_username(&self) -> Column<Advice>;

    fn get_concatenated_balance(&self) -> Column<Advice>;

    fn get_balances(&self) -> [Column<Advice>; N_CURRENCIES];

    fn get_instance(&self) -> Column<Instance>;

    /// Assigns the entries to the circuit, constrains the grand total to the instance values.
    fn synthesize(
        &self,
        mut layouter: impl Layouter<Fp>,
        entries: &[Entry<N_USERS, N_CURRENCIES>],
        concatenated_grand_total: &Fp,
    ) -> Result<(), Error> {
        // Initiate the range check chips
        let range_check_chips = self.initialize_range_check_chips();

        for (i, entry) in entries.iter().enumerate() {
            let last_decompositions = layouter.assign_region(
                || format!("assign entry {} to the table", i),
                |mut region| {
                    region.assign_advice(
                        || "username",
                        self.get_username(),
                        0,
                        || Value::known(big_uint_to_fp::<Fp>(entry.username_as_big_uint())),
                    )?;

                    region.assign_advice(
                        || "concatenated balance",
                        self.get_concatenated_balance(),
                        0,
                        || {
                            Value::known(big_uint_to_fp::<Fp>(
                                &entry.concatenated_balance().unwrap(),
                            ))
                        },
                    )?;

                    // Decompose the balances
                    let mut assigned_balances = Vec::new();

                    for (j, balance) in entry.balances().iter().enumerate() {
                        let assigned_balance = region.assign_advice(
                            || format!("balance {}", j),
                            self.get_balances()[j],
                            0,
                            || Value::known(big_uint_to_fp(balance)),
                        )?;

                        assigned_balances.push(assigned_balance);
                    }

                    let mut last_decompositions = vec![];

                    for (j, assigned_balance) in assigned_balances.iter().enumerate() {
                        let mut zs = Vec::with_capacity(4);

                        if !range_check_chips.is_empty() {
                            range_check_chips[j].assign(&mut region, &mut zs, assigned_balance)?;

                            last_decompositions.push(zs[3].clone());
                        }
                    }

                    Ok(last_decompositions)
                },
            )?;

            self.constrain_decompositions(last_decompositions, &mut layouter)?;
        }

        let assigned_total = layouter.assign_region(
            || "assign concatenated total".to_string(),
            |mut region| {
                let balance_total = region.assign_advice(
                    || format!("concateneated total({} currencies)", N_CURRENCIES),
                    self.get_concatenated_balance(),
                    0,
                    || Value::known(concatenated_grand_total.neg()),
                )?;

                Ok(balance_total)
            },
        )?;

        layouter.constrain_instance(assigned_total.cell(), self.get_instance(), 1)?;

        self.load_lookup_table(layouter)?;

        Ok(())
    }

    /// Initializes the range check chips
    fn initialize_range_check_chips(&self) -> Vec<RangeCheckU64Chip>;

    /// Loads the lookup table
    fn load_lookup_table(&self, layouter: impl Layouter<Fp>) -> Result<(), Error>;

    /// Constrains the last decompositions of the balances to be zero
    fn constrain_decompositions(
        &self,
        last_decompositions: Vec<halo2_proofs::circuit::AssignedCell<Fp, Fp>>,
        layouter: &mut impl Layouter<Fp>,
    ) -> Result<(), Error>;
}
