use crate::chips::range::range_check::{RangeCheckU64Chip, RangeCheckU64Config};
use crate::entry::Entry;
use crate::utils::big_uint_to_fp;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed};

#[derive(Clone)]
pub struct UnivariateGrandSum<const N_USERS: usize, const N_CURRENCIES: usize> {
    pub entries: Vec<Entry<N_CURRENCIES>>,
}

impl<const N_USERS: usize, const N_CURRENCIES: usize> UnivariateGrandSum<N_USERS, N_CURRENCIES> {
    pub fn init_empty() -> Self {
        Self {
            entries: vec![Entry::init_empty(); N_USERS],
        }
    }

    /// Initializes the circuit with the user entries that are part of the solvency proof
    pub fn init(user_entries: Vec<Entry<N_CURRENCIES>>) -> Self {
        Self {
            entries: user_entries,
        }
    }
}

/// Configuration for the Mst Inclusion circuit
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of currencies for which the solvency is verified.
///
/// # Fields
///
/// * `username`: Advice column used to store the usernames of the users
/// * `balances`: Advice columns used to store the balances of the users
/// * `range_check_configs`: Configurations for the range check chip
/// * `range_u16`: Fixed column used to store the lookup table [0, 2^16 - 1] for the range check chip
#[derive(Debug, Clone)]
pub struct UnivariateGrandSumConfig<const N_CURRENCIES: usize>
where
    [(); N_CURRENCIES + 1]:,
{
    username: Column<Advice>,
    balances: [Column<Advice>; N_CURRENCIES],
    range_check_configs: [RangeCheckU64Config; N_CURRENCIES],
    range_u16: Column<Fixed>,
}

impl<const N_CURRENCIES: usize> UnivariateGrandSumConfig<N_CURRENCIES>
where
    [(); N_CURRENCIES + 1]:,
{
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        let username = meta.advice_column();

        let balances = [(); N_CURRENCIES].map(|_| meta.unblinded_advice_column());

        let range_u16 = meta.fixed_column();

        meta.enable_constant(range_u16);

        meta.annotate_lookup_any_column(range_u16, || "LOOKUP_MAXBITS_RANGE");

        // Create an empty array of range check configs
        let mut range_check_configs = Vec::with_capacity(N_CURRENCIES);

        for i in 0..N_CURRENCIES {
            let z = balances[i];
            // Create 4 advice columns for each range check chip
            let zs = [(); 4].map(|_| meta.advice_column());

            for column in zs.iter() {
                meta.enable_equality(*column);
            }

            let range_check_config = RangeCheckU64Chip::configure(meta, z, zs, range_u16);

            range_check_configs.push(range_check_config);
        }

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            username,
            balances,
            range_check_configs: range_check_configs.try_into().unwrap(),
            range_u16,
        }
    }
    /// Assigns the entries to the circuit
    /// At row i, the username is set to the username of the i-th entry, the balance is set to the balance of the i-th entry
    /// Returns a bidimensional vector of the assigned balances to the circuit.
    pub fn assign_entries(
        &self,
        mut layouter: impl Layouter<Fp>,
        entries: &[Entry<N_CURRENCIES>],
    ) -> Result<Vec<Vec<AssignedCell<Fp, Fp>>>, Error> {
        layouter.assign_region(
            || "assign entries to the table",
            |mut region| {
                // create a bidimensional vector to store the assigned balances. The first dimension is N_USERS, the second dimension is N_CURRENCIES
                let mut assigned_balances = vec![];

                for (i, entry) in entries.iter().enumerate() {
                    region.assign_advice(
                        || "username",
                        self.username,
                        i,
                        || Value::known(big_uint_to_fp(entry.username_as_big_uint())),
                    )?;

                    let mut assigned_balances_row = vec![];

                    for (j, balance) in entry.balances().iter().enumerate() {
                        let assigned_balance = region.assign_advice(
                            || format!("balance {}", j),
                            self.balances[j],
                            i,
                            || Value::known(big_uint_to_fp(balance)),
                        )?;

                        assigned_balances_row.push(assigned_balance);
                    }

                    assigned_balances.push(assigned_balances_row);
                }

                Ok(assigned_balances)
            },
        )
    }
}

impl<const N_USERS: usize, const N_CURRENCIES: usize> Circuit<Fp>
    for UnivariateGrandSum<N_USERS, N_CURRENCIES>
where
    [(); N_CURRENCIES + 1]:,
{
    type Config = UnivariateGrandSumConfig<N_CURRENCIES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    /// Configures the circuit
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        UnivariateGrandSumConfig::<N_CURRENCIES>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Initiate the range check chips
        let range_check_chips = config
            .range_check_configs
            .iter()
            .map(|config| RangeCheckU64Chip::construct(*config))
            .collect::<Vec<_>>();

        // Load lookup table for range check u64 chip
        let range = 1 << 16;

        layouter.assign_region(
            || format!("load range check table of 16 bits"),
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

        // Assign entries
        let assigned_balances =
            config.assign_entries(layouter.namespace(|| "assign entries"), &self.entries)?;

        // Perform range check on the assigned balances
        for i in 0..N_USERS {
            for j in 0..N_CURRENCIES {
                layouter.assign_region(
                    || format!("Perform range check on balance {} of user {}", j, i),
                    |mut region| {
                        range_check_chips[j].assign(&mut region, &assigned_balances[i][j])?;
                        Ok(())
                    },
                )?;
            }
        }

        Ok(())
    }
}
