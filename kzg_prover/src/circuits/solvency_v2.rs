use crate::entry::Entry;
use crate::utils::big_uint_to_fp;
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed};

#[derive(Clone)]
pub struct SolvencyV2<const N_BYTES: usize, const N_USERS: usize, const N_ASSETS: usize> {
    pub entries: Vec<Entry<N_ASSETS>>,
}

impl<const N_BYTES: usize, const N_USERS: usize, const N_ASSETS: usize>
    SolvencyV2<N_BYTES, N_USERS, N_ASSETS>
{
    pub fn init_empty() -> Self {
        Self {
            entries: vec![Entry::init_empty(); N_USERS],
        }
    }

    /// Initializes the circuit with the user entries that are part of the solvency proof
    pub fn init(user_entries: Vec<Entry<N_ASSETS>>) -> Self {
        Self {
            entries: user_entries,
        }
    }
}

/// Configuration for the Mst Inclusion circuit
/// # Type Parameters
///
/// * `N_BYTES`: The number of bytes in which the balances should lie
///
/// # Fields
///
/// * `range_check_config`: Configuration for the range check chip
/// * `advices`: Advice columns used to store the private inputs
#[derive(Debug, Clone)]
pub struct SolvencyV2Config<const N_BYTES: usize, const N_ASSETS: usize>
where
    [(); N_ASSETS + 1]:,
{
    advices: [Column<Advice>; N_ASSETS + 1],
    range: Column<Fixed>,
}

impl<const N_BYTES: usize, const N_ASSETS: usize> SolvencyV2Config<N_BYTES, N_ASSETS>
where
    [(); N_ASSETS + 1]:,
{
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // We need 1 advice column for the username, N_ASSETS for the balances. The advice column for the balances is passed to the `range_check_chip`
        //TODO: unblinded only for the balances, usernames can stay blinded
        let advices: [Column<Advice>; N_ASSETS + 1] =
            std::array::from_fn(|_| meta.unblinded_advice_column());

        // we need a fixed column for the range check
        let range = meta.fixed_column();

        meta.enable_constant(range);

        meta.annotate_lookup_any_column(range, || "LOOKUP_MAXBITS_RANGE");

        // meta.lookup_any("advice cell should be in range [0, 2^8 - 1]", |meta| {
        //     let balance = meta.query_advice(advices[1], Rotation::cur());
        //     let u8_range = meta.query_fixed(range, Rotation::cur());

        //     vec![(balance, u8_range)]
        // });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self { advices, range }
    }

    /// Assigns the entries to the circuit
    /// At row i, the username is set to the username of the i-th entry, the balance is set to the balance of the i-th entry
    pub fn assign_entries(
        &self,
        mut layouter: impl Layouter<Fp>,
        entries: &[Entry<N_ASSETS>],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign entries and accumulated balance to table",
            |mut region| {
                for (i, entry) in entries.iter().enumerate() {
                    region.assign_advice(
                        || "username",
                        self.advices[0],
                        i,
                        || Value::known(big_uint_to_fp(entry.username_as_big_uint())),
                    )?;

                    for (j, balance) in entry.balances().iter().enumerate() {
                        region.assign_advice(
                            || format!("balance {}", j),
                            self.advices[j + 1],
                            i,
                            || Value::known(big_uint_to_fp(balance)),
                        )?;
                    }
                }

                Ok(())
            },
        )
    }
}

impl<const N_BYTES: usize, const N_USERS: usize, const N_ASSETS: usize> Circuit<Fp>
    for SolvencyV2<N_BYTES, N_USERS, N_ASSETS>
where
    [(); N_ASSETS + 1]:,
{
    type Config = SolvencyV2Config<N_BYTES, N_ASSETS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    /// Configures the circuit
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        SolvencyV2Config::<N_BYTES, N_ASSETS>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Assign entries
        config.assign_entries(layouter.namespace(|| "assign entries"), &self.entries)?;

        // Load lookup table to perform range check on individual balances -> Each balance should be in the range [0, 2^8 - 1]
        let range = 1 << (8);

        layouter.assign_region(
            || format!("load range check table of {} bits", 8),
            |mut region| {
                for i in 0..range {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        config.range,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )?;

        Ok(())
    }
}
