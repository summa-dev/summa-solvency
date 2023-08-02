use crate::chips::less_than::less_than_vertical::{
    LtVerticalChip, LtVerticalConfig, LtVerticalInstruction,
};
use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::merkle_sum_tree::MerkleSumTree;
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
};
use halo2_proofs::poly::Rotation;
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
pub struct SolvencyCircuit<const N_ASSETS: usize> {
    pub left_node_hash: Fp,
    pub left_node_balances: [Fp; N_ASSETS],
    pub right_node_hash: Fp,
    pub right_node_balances: [Fp; N_ASSETS],
    pub asset_sums: [Fp; N_ASSETS],
    pub root_hash: Fp,
}

impl<const N_ASSETS: usize> CircuitExt<Fp> for SolvencyCircuit<N_ASSETS>
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

impl<const N_ASSETS: usize> SolvencyCircuit<N_ASSETS> {
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
    pub fn init(merkle_sum_tree: MerkleSumTree<N_ASSETS>, asset_sums: [Fp; N_ASSETS]) -> Self {
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
pub struct SolvencyConfig<const N_ASSETS: usize>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub merkle_sum_tree_config: MerkleSumTreeConfig,
    pub poseidon_config: PoseidonConfig<2, 1, { 2 * (1 + N_ASSETS) }>,
    pub instance: Column<Instance>,
    pub lt_selector: Selector,
    pub lt_config: LtVerticalConfig<8>,
}

impl<const N_ASSETS: usize> SolvencyConfig<N_ASSETS>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    /// Configures the circuit
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // the max number of advices columns needed is #WIDTH + 1 given requirement of the poseidon config
        let advices: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());

        // the max number of fixed columns needed is 2 * WIDTH given requirement of the poseidon config
        let fixed_columns: [Column<Fixed>; 4] = std::array::from_fn(|_| meta.fixed_column());

        // we also need 4 selectors - 3 simple selectors and 1 complex selector
        let selectors: [Selector; 3] = std::array::from_fn(|_| meta.selector());
        let complex_selector = meta.complex_selector();

        // in fact, the poseidon config requires #WIDTH advice columns for state and 1 for partial_sbox, #WIDTH fixed columns for rc_a and #WIDTH for rc_b
        let poseidon_config = PoseidonChip::<PoseidonSpec, 2, 1, { 2 * (1 + N_ASSETS) }>::configure(
            meta,
            advices[0..2].try_into().unwrap(),
            advices[2],
            fixed_columns[0..2].try_into().unwrap(),
            fixed_columns[2..4].try_into().unwrap(),
        );

        // enable permutation for all the advice columns
        for col in &advices {
            meta.enable_equality(*col);
        }

        // the configuration of merkle_sum_tree will always require 3 advices, no matter the number of assets
        let merkle_sum_tree_config = MerkleSumTreeChip::<N_ASSETS>::configure(
            meta,
            advices[0..3].try_into().unwrap(),
            selectors[0..2].try_into().unwrap(),
        );

        let lt_selector = selectors[2];

        // configure lt chip
        let lt_config = LtVerticalChip::configure(
            meta,
            |meta| meta.query_selector(lt_selector),
            |meta| meta.query_advice(advices[0], Rotation::prev()),
            |meta| meta.query_advice(advices[0], Rotation::cur()),
            advices[1],
            advices[2],
            fixed_columns[0],
            complex_selector,
        );

        // Gate that enforces that the result of the lt chip is 1 at the row in which the lt selector is enabled
        meta.create_gate("is_lt is 1", |meta| {
            let lt_enable = meta.query_selector(lt_selector);
            vec![lt_enable * (lt_config.is_lt(meta, None) - Expression::Constant(Fp::from(1)))]
        });

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            merkle_sum_tree_config,
            poseidon_config,
            lt_config,
            lt_selector,
            instance,
        }
    }

    /// Enforces value in the cell passed as input to be less than the value in the instance column at row `index`.
    pub fn enforce_less_than(
        &self,
        mut layouter: impl Layouter<Fp>,
        input_cell: &AssignedCell<Fp, Fp>,
        index: usize,
        lt_chip: &LtVerticalChip<8>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "enforce input cell to be less than value in instance column at row `index`",
            |mut region| {
                // First, copy the input cell inside the region
                let lhs = input_cell.copy_advice(
                    || "copy input sum",
                    &mut region,
                    self.merkle_sum_tree_config.advice[0],
                    0,
                )?;

                // Next, copy the value from the instance columns
                let rhs = region.assign_advice_from_instance(
                    || "copy value from instance column",
                    self.instance,
                    index,
                    self.merkle_sum_tree_config.advice[0],
                    1,
                )?;

                // enable lt seletor
                self.lt_selector.enable(&mut region, 1)?;

                lt_chip.assign(&mut region, 1, lhs.value().copied(), rhs.value().copied())?;

                Ok(())
            },
        )?;

        Ok(())
    }

    /// Enforces copy constraint check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.instance, row)
    }
}

impl<const N_ASSETS: usize> Circuit<Fp> for SolvencyCircuit<N_ASSETS>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    type Config = SolvencyConfig<N_ASSETS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        SolvencyConfig::<N_ASSETS>::configure(meta)
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
        let lt_chip = LtVerticalChip::<8>::construct(config.lt_config);

        // Assign the left penultimate hash and the left penultimate balances
        let (left_node_hash, left_node_balances) = merkle_sum_tree_chip
            .assign_entry_hash_and_balances(
                layouter.namespace(|| "assign leaf hash and balances"),
                self.left_node_hash,
                &self.left_node_balances,
            )?;

        let swap_bit = merkle_sum_tree_chip
            .assing_swap_bit(layouter.namespace(|| "assign swap bit"), Fp::from(0))?;

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
        config.expose_public(layouter.namespace(|| "public root hash"), &root_hash, 0)?;

        // load lookup table for lt chip
        lt_chip.load(&mut layouter)?;

        // enforce root balances to be less than the assets sum
        for asset in 0..N_ASSETS {
            config.enforce_less_than(
                layouter.namespace(|| "enforce less than"),
                &root_balances[asset],
                asset + 1,
                &lt_chip,
            )?;
        }

        Ok(())
    }
}
