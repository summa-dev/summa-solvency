use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::chips::range::range_check::{RangeCheckChip, RangeCheckConfig};
use crate::merkle_sum_tree::{big_uint_to_fp, MerkleSumTree};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
};
use snark_verifier_sdk::CircuitExt;

/// Circuit for verifying inclusion of a leaf_hash inside a merkle sum tree with a given root.
///
/// # Type Parameters
///
/// * `LEVELS`: The number of levels of the merkle sum tree
/// * `N_ASSETS`: The number of assets for which the solvency is verified.
/// * `N_BYTES`: The number of bytes in which the balances should lie
///
/// # Fields
///
/// * `leaf_hash`: The hash of the leaf to be verified inclusion of
/// * `leaf_balances`: The balances of the leaf to be verified inclusion of. The length of this vector is N_ASSETS
/// * `path_element_hashes`: The hashes of the path elements from the leaf to root. The length of this vector is LEVELS
/// * `path_element_balances`: The balances of the path elements from the leaf to the root. The length of this vector is LEVELS
/// * `path_indices`: The boolean indices of the path elements from the leaf to the root. 0 indicates that the element is on the right to the path, 1 indicates that the element is on the left to the path. The length of this vector is LEVELS
#[derive(Clone)]
pub struct MstInclusionCircuit<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> {
    pub leaf_hash: Fp,
    pub leaf_balances: Vec<Fp>,
    pub path_element_hashes: Vec<Fp>,
    pub path_element_balances: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
    pub root_hash: Fp,
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> CircuitExt<Fp>
    for MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    /// Returns the number of public inputs of the circuit. It is 2, namely the laef hash to be verified inclusion of and the root hash of the merkle sum tree.
    fn num_instance(&self) -> Vec<usize> {
        vec![2]
    }
    /// Returns the values of the public inputs of the circuit. Namely the leaf hash to be verified inclusion of and the root hash of the merkle sum tree.
    fn instances(&self) -> Vec<Vec<Fp>> {
        vec![vec![self.leaf_hash, self.root_hash]]
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
{
    pub fn init_empty() -> Self {
        Self {
            leaf_hash: Fp::zero(),
            leaf_balances: vec![Fp::zero(); N_ASSETS],
            path_element_hashes: vec![Fp::zero(); LEVELS],
            path_element_balances: vec![[Fp::zero(); N_ASSETS]; LEVELS],
            path_indices: vec![Fp::zero(); LEVELS],
            root_hash: Fp::zero(),
        }
    }

    /// Initializes the circuit with the merkle sum tree and the index of the user of which the inclusion is to be verified.
    pub fn init(merkle_sum_tree: MerkleSumTree<N_ASSETS, N_BYTES>, user_index: usize) -> Self
    where
        [usize; N_ASSETS + 1]:,
    {
        let proof = merkle_sum_tree.generate_proof(user_index).unwrap();

        assert_eq!(proof.path_indices.len(), LEVELS);
        assert_eq!(proof.sibling_hashes.len(), LEVELS);
        assert_eq!(proof.sibling_sums.len(), LEVELS);

        Self {
            leaf_hash: proof.entry.compute_leaf().hash,
            leaf_balances: proof
                .entry
                .balances()
                .iter()
                .map(big_uint_to_fp)
                .collect::<Vec<_>>(),
            path_element_hashes: proof.sibling_hashes,
            path_element_balances: proof.sibling_sums,
            path_indices: proof.path_indices,
            root_hash: proof.root_hash,
        }
    }
}

/// Configuration for the Mst Inclusion circuit
/// # Type Parameters
///
/// * `N_ASSETS`: The number of assets for which the solvency is verified.
/// * `N_BYTES`: The number of bytes in which the balances should lie
///
/// # Fields
///
/// * `merkle_sum_tree_config`: Configuration for the merkle sum tree
/// * `poseidon_config`: Configuration for the poseidon hash function with WIDTH = 2 and RATE = 1
/// * `range_check_config`: Configuration for the range check chip
/// * `instance`: Instance column used to store the public inputs

#[derive(Debug, Clone)]
pub struct MstInclusionConfig<const N_ASSETS: usize, const N_BYTES: usize>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub merkle_sum_tree_config: MerkleSumTreeConfig,
    pub poseidon_config: PoseidonConfig<2, 1, { 2 * (1 + N_ASSETS) }>,
    pub range_check_config: RangeCheckConfig<N_BYTES>,
    pub instance: Column<Instance>,
}

impl<const N_ASSETS: usize, const N_BYTES: usize> MstInclusionConfig<N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // the max number of advices columns needed is WIDTH + 1 given requirement of the poseidon config
        let advices: [Column<Advice>; 3] = std::array::from_fn(|_| meta.advice_column());

        // we need 2 * WIDTH fixed columns for poseidon config + 1 for the range check chip
        let fixed_columns: [Column<Fixed>; 5] = std::array::from_fn(|_| meta.fixed_column());

        // we also need 2 selectors for the MerkleSumTreeChip
        let selectors: [Selector; 2] = std::array::from_fn(|_| meta.selector());

        // we need 1 complex selector for the lookup check in the range check chip
        let toggle_lookup_check = meta.complex_selector();

        // enable constant for the fixed_column[2], this is required for the poseidon chip and the range check chip
        meta.enable_constant(fixed_columns[2]);

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

        let range_check_config = RangeCheckChip::<N_BYTES>::configure(
            meta,
            advices[0],
            fixed_columns[4],
            toggle_lookup_check,
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            merkle_sum_tree_config,
            poseidon_config,
            range_check_config,
            instance,
        }
    }

    /// Enforce copy constraint check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.instance, row)
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> Circuit<Fp>
    for MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    type Config = MstInclusionConfig<N_ASSETS, N_BYTES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    /// Configures the circuit
    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        MstInclusionConfig::<N_ASSETS, N_BYTES>::configure(meta)
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
        let range_check_chip =
            RangeCheckChip::<N_BYTES>::construct(config.range_check_config.clone());

        // Assign the leaf hash and the leaf balances
        let (mut current_hash, mut current_balances) = merkle_sum_tree_chip
            .assign_entry_hash_and_balances(
                layouter.namespace(|| "assign leaf hash and balances"),
                self.leaf_hash,
                &self.leaf_balances,
            )?;

        // expose the first current hash, namely the leaf hash, as public input
        config.expose_public(layouter.namespace(|| "public leaf hash"), &current_hash, 0)?;

        // load range check chip
        range_check_chip.load(&mut layouter)?;

        for level in 0..LEVELS {
            let namespace_prefix = format!("level {}", level);

            // For each level assign the index to the circuit
            let swap_bit_level = merkle_sum_tree_chip.assing_swap_bit(
                layouter.namespace(|| format!("{}: assign swap bit", namespace_prefix)),
                self.path_indices[level],
            )?;

            // For each level assign the hashes to the circuit
            let (hash_left_current, hash_right_current) = merkle_sum_tree_chip
                .assign_nodes_hashes_per_level(
                    layouter.namespace(|| format!("{}: assign nodes hashes", namespace_prefix)),
                    &current_hash,
                    self.path_element_hashes[level],
                    swap_bit_level.clone(),
                )?;

            let mut next_balances = vec![];
            let mut left_balances = vec![];
            let mut right_balances = vec![];

            // Within each level, assign the balances to the circuit per asset
            for asset in 0..N_ASSETS {
                let (left_balance, right_balance, next_balance) = merkle_sum_tree_chip
                    .assign_nodes_balance_per_asset(
                        layouter.namespace(|| {
                            format!(
                                "{}: asset {}: assign nodes balance",
                                namespace_prefix, asset
                            )
                        }),
                        &current_balances[asset],
                        self.path_element_balances[level][asset],
                        swap_bit_level.clone(),
                    )?;

                // Each balance cell is constrained to be within the range defined by N_BYTES
                range_check_chip.assign(
                    layouter.namespace(|| {
                        format!(
                            "{}: asset {}: range check left balance",
                            namespace_prefix, asset
                        )
                    }),
                    &left_balance,
                )?;
                range_check_chip.assign(
                    layouter.namespace(|| {
                        format!(
                            "{}: asset {}: range check right balance",
                            namespace_prefix, asset
                        )
                    }),
                    &right_balance,
                )?;

                next_balances.push(next_balance);
                left_balances.push(left_balance);
                right_balances.push(right_balance);
            }

            // create an hash_input array of length L that contains the left hash, the left balances, the right hash and the right balances
            let hash_input_vec: Vec<AssignedCell<Fp, Fp>> = [hash_left_current]
                .iter()
                .chain(left_balances.iter())
                .chain([hash_right_current].iter())
                .chain(right_balances.iter())
                .map(|x| x.to_owned())
                .collect();

            let hash_input: [AssignedCell<Fp, Fp>; 2 * (1 + N_ASSETS)] =
                match hash_input_vec.try_into() {
                    Ok(arr) => arr,
                    Err(_) => panic!("Failed to convert Vec to Array"),
                };

            // compute the next hash
            let computed_hash = poseidon_chip.hash(
                layouter.namespace(|| format!("{}: perform poseidon hash", namespace_prefix)),
                hash_input,
            )?;

            current_balances = next_balances;
            current_hash = computed_hash;
        }

        // expose the last current hash, namely the root hash, as public input
        config.expose_public(layouter.namespace(|| "public root hash"), &current_hash, 1)?;

        // perform range check on the balances of the root to make sure these lie in the range defined by N_BYTES
        for balance in current_balances.iter() {
            range_check_chip.assign(layouter.namespace(|| "range check root balance"), balance)?;
        }

        Ok(())
    }
}
