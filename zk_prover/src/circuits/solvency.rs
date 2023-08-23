use crate::chips::less_than_check::lt_check::{CheckLtChip, CheckLtConfig};
use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::circuits::traits::CircuitBase;
use crate::merkle_sum_tree::MerkleSumTree;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
};
use snark_verifier_sdk::CircuitExt;

/// Circuit for verifying solvency, namely that the asset_sums is greater than the sum of the liabilities stored in the merkle sum tree
///
/// # Type Parameters
///
/// * `N_ASSETS`: The number of assets for which the solvency is verified.
/// * `N_BYTES`: Range in which the balances should lie
///
/// # Fields
///
/// * `left_node_hash`: The hash of the penultimate left node of the merkle sum tree
/// * `left_node_balances`: The balances of the penultimate left node of the merkle sum tree
/// * `right_node_hash`: The hash of the penultimate right node of the merkle sum tree
/// * `right_node_balances`: The balances of the penultimate right node of the merkle sum tree
/// * `asset_sums`: The sum of the assets of the CEX for each asset
/// * `root_hash`: The root hash of the merkle sum tree
#[derive(Clone)]
pub struct SolvencyCircuit<const N_ASSETS: usize, const N_BYTES: usize> {
    pub left_node_hash: Fp,
    pub left_node_balances: [Fp; N_ASSETS],
    pub right_node_hash: Fp,
    pub right_node_balances: [Fp; N_ASSETS],
    pub asset_sums: [Fp; N_ASSETS],
    pub root_hash: Fp,
}

impl<const N_ASSETS: usize, const N_BYTES: usize> CircuitBase
    for SolvencyCircuit<N_ASSETS, N_BYTES>
{
}

impl<const N_ASSETS: usize, const N_BYTES: usize> CircuitExt<Fp>
    for SolvencyCircuit<N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    /// Returns the number of public inputs of the circuit. It is 1 + N_ASSETS, namely the root hash of the merkle sum tree and the sum of the assets of the CEX for each asset
    fn num_instance(&self) -> Vec<usize> {
        vec![1 + N_ASSETS]
    }

    /// Returns the values of the public inputs of the circuit. The first value is the root hash of the merkle sum tree and the remaining values are the sum of the assets of the CEX for each asset
    fn instances(&self) -> Vec<Vec<Fp>> {
        let mut instances = vec![self.root_hash];
        instances.extend(self.asset_sums);
        vec![instances]
    }
}

impl<const N_ASSETS: usize, const N_BYTES: usize> SolvencyCircuit<N_ASSETS, N_BYTES> {
    pub fn init_empty() -> Self {
        Self {
            left_node_hash: Fp::zero(),
            left_node_balances: [Fp::zero(); N_ASSETS],
            right_node_hash: Fp::zero(),
            right_node_balances: [Fp::zero(); N_ASSETS],
            asset_sums: [Fp::zero(); N_ASSETS],
            root_hash: Fp::zero(),
        }
    }

    /// Initializes the circuit with the merkle sum tree and the assets sum
    pub fn init(
        merkle_sum_tree: MerkleSumTree<N_ASSETS, N_BYTES>,
        asset_sums: [Fp; N_ASSETS],
    ) -> Self {
        let (penultimate_node_left, penultimate_node_right) = merkle_sum_tree
            .penultimate_level_data()
            .expect("Failed to retrieve penultimate level data");

        let root_hash = merkle_sum_tree.root().hash;

        Self {
            left_node_hash: penultimate_node_left.hash,
            left_node_balances: penultimate_node_left.balances,
            right_node_hash: penultimate_node_right.hash,
            right_node_balances: penultimate_node_right.balances,
            asset_sums,
            root_hash,
        }
    }
}

/// Configuration for the solvency circuit
/// # Type Parameters
///
/// * `N_ASSETS`: The number of assets for which the solvency is verified.
/// * `N_BYTES`: Range in which the balances should lie
///
/// # Fields
///
/// * `merkle_sum_tree_config`: Configuration for the merkle sum tree
/// * `poseidon_config`: Configuration for the poseidon hash function with WIDTH = 2 and RATE = 1
/// * `instance`: Instance column used to store the public inputs
/// * `lt_selector`: Selector to activate the less than constraint
/// * `lt_config`: Configuration for the less than chip
///
/// The circuit performs an additional constraint:
/// * `lt_enable * (lt_config.is_lt - 1) = 0` (if `lt_enable` is toggled). It basically enforces the result of the less than chip to be 1.
#[derive(Debug, Clone)]
pub struct SolvencyConfig<const N_ASSETS: usize, const N_BYTES: usize>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    advice_cols: [Column<Advice>; 3],
    merkle_sum_tree_config: MerkleSumTreeConfig,
    poseidon_config: PoseidonConfig<2, 1, { 2 * (1 + N_ASSETS) }>,
    instance: Column<Instance>,
    check_lt_config: CheckLtConfig<N_BYTES>,
}

impl<const N_ASSETS: usize, const N_BYTES: usize> SolvencyConfig<N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    /// Configures the circuit
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // the max number of advices columns needed is #WIDTH + 1 given requirement of the poseidon config
        let advice_cols: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());

        // the max number of fixed columns needed is 2 * WIDTH given requirement of the poseidon config
        let fixed_columns: [Column<Fixed>; 4] = std::array::from_fn(|_| meta.fixed_column());

        // we also need 4 selectors - 3 simple selectors and 1 complex selector
        let selectors: [Selector; 3] = std::array::from_fn(|_| meta.selector());
        let enable_lookup_selector = meta.complex_selector();

        // enable constant for the fixed_column[2], this is required for the poseidon chip
        meta.enable_constant(fixed_columns[2]);

        // in fact, the poseidon config requires #WIDTH advice columns for state and 1 for partial_sbox, #WIDTH fixed columns for rc_a and #WIDTH for rc_b
        let poseidon_config = PoseidonChip::<PoseidonSpec, 2, 1, { 2 * (1 + N_ASSETS) }>::configure(
            meta,
            advice_cols[0..2].try_into().unwrap(),
            advice_cols[2],
            fixed_columns[0..2].try_into().unwrap(),
            fixed_columns[2..4].try_into().unwrap(),
        );

        // enable permutation for all the advice columns
        for col in &advice_cols {
            meta.enable_equality(*col);
        }

        // the configuration of merkle_sum_tree will always require 3 advices, no matter the number of assets
        let merkle_sum_tree_config = MerkleSumTreeChip::<N_ASSETS>::configure(
            meta,
            advice_cols[0..3].try_into().unwrap(),
            selectors[0..2].try_into().unwrap(),
        );

        // configure check lt chip
        let check_lt_config = CheckLtChip::<N_BYTES>::configure(
            meta,
            advice_cols[0],
            advice_cols[1],
            advice_cols[2],
            fixed_columns[0],
            selectors[2],
            enable_lookup_selector,
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            advice_cols,
            merkle_sum_tree_config,
            poseidon_config,
            check_lt_config,
            instance,
        }
    }

    /// Generic method to assign witness value to a cell in the witness table to advice column `column_index`. `object_to_assign` is label to identify the object being assigned. It is useful for debugging.
    pub fn assign_value_to_witness(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Fp,
        column_index: usize,
        object_to_assign: &'static str,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || format!("assign {}", object_to_assign),
            |mut region| {
                region.assign_advice(
                    || "value",
                    self.advice_cols[column_index],
                    0,
                    || Value::known(value),
                )
            },
        )
    }
}

impl<const N_ASSETS: usize, const N_BYTES: usize> Circuit<Fp> for SolvencyCircuit<N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    type Config = SolvencyConfig<N_ASSETS, N_BYTES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        SolvencyConfig::<N_ASSETS, N_BYTES>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // build auxiliary chips
        let merkle_sum_tree_chip =
            MerkleSumTreeChip::<N_ASSETS>::construct(config.merkle_sum_tree_config.clone());
        let poseidon_chip = PoseidonChip::<PoseidonSpec, 2, 1, { 2 * (1 + N_ASSETS) }>::construct(
            config.poseidon_config.clone(),
        );
        let check_lt_chip = CheckLtChip::<N_BYTES>::construct(config.check_lt_config);

        // assign asset sums value to the witness
        let asset_sums = self
            .asset_sums
            .iter()
            .enumerate()
            .map(|(i, sum)| {
                config.assign_value_to_witness(
                    layouter.namespace(|| format!("assign asset sum {}", i)),
                    *sum,
                    0,
                    "asset sum",
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Assign the penultimate left node hash and the penultimate left node balances following this layout on two columns:
        //
        // | a                     | b                          |
        // | --------------------- | -------------------------- |
        // | left_node_hash        | left_node_balances_0       |
        // | -                     | left_node_balances_1       |
        // | -                     | ...                        |
        // | -                     | left_node_balances_N       |

        let left_node_hash = self.assign_value_to_witness(
            layouter.namespace(|| "assign penultimate left node hash"),
            self.left_node_hash,
            "left node hash",
            config.advice_cols[0],
        )?;

        let left_node_balances = self
            .left_node_balances
            .iter()
            .enumerate()
            .map(|(i, balance)| {
                self.assign_value_to_witness(
                    layouter.namespace(|| format!("assign entry balance {}", i)),
                    *balance,
                    "left node balance",
                    config.advice_cols[1],
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // assign swap bit
        let swap_bit = self.assign_value_to_witness(
            layouter.namespace(|| "assign swap bit"),
            Fp::from(0),
            "swap bit",
            config.advice_cols[2],
        )?;

        // assign penultimate nodes hashes according to the swap bit
        let (left_hash, right_hash) = merkle_sum_tree_chip.assign_nodes_hashes_per_level(
            layouter.namespace(|| "assign penultimate nodes hashes"),
            &left_node_hash,
            self.right_node_hash,
            swap_bit.clone(),
        )?;

        let mut root_balances = vec![];
        let mut left_balances = vec![];
        let mut right_balances = vec![];

        // assign penultimate nodes balances per each asset according to the swap bit
        for asset in 0..N_ASSETS {
            let (left_balance, right_balance, next_balance) = merkle_sum_tree_chip
                .assign_nodes_balance_per_asset(
                    layouter.namespace(|| format!("asset {}: assign nodes balances", asset)),
                    &left_node_balances[asset],
                    self.right_node_balances[asset],
                    swap_bit.clone(),
                )?;

            root_balances.push(next_balance);
            left_balances.push(left_balance);
            right_balances.push(right_balance);
        }

        // create an hash_input array of length L that contains the left hash, the left balances, the right hash and the right balances
        let hash_input_vec: Vec<AssignedCell<Fp, Fp>> = [left_hash]
            .iter()
            .chain(left_balances.iter())
            .chain([right_hash].iter())
            .chain(right_balances.iter())
            .map(|x| x.to_owned())
            .collect();

        let hash_input: [AssignedCell<Fp, Fp>; 2 * (1 + N_ASSETS)] = match hash_input_vec.try_into()
        {
            Ok(arr) => arr,
            Err(_) => panic!("Failed to convert Vec to Array"),
        };

        // compute the root hash
        let root_hash = poseidon_chip.hash(
            layouter.namespace(|| format!("perform root hash")),
            hash_input,
        )?;

        // expose the root hash, as public input
        self.expose_public(
            layouter.namespace(|| "public root hash"),
            &root_hash,
            0,
            config.instance,
        )?;

        // enforce root balances to be less than the assets sum
        for i in 0..N_ASSETS {
            check_lt_chip.assign(
                layouter.namespace(|| "enforce less than"),
                &root_balances[i],
                &asset_sums[i],
            )?;
        }

        Ok(())
    }
}
