use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::chips::range::range_check::{RangeCheckChip, RangeCheckConfig};
use crate::circuits::traits::CircuitBase;
use crate::merkle_sum_tree::{big_uint_to_fp, Entry, MerkleProof};
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
/// * `entry`: The entry to be verified inclusion of.
/// * `path_element_hashes`: The hashes of the path elements from the leaf to root. The length of this vector is LEVELS
/// * `path_element_balances`: The balances of the path elements from the leaf to the root. The length of this vector is LEVELS
/// * `path_indices`: The boolean indices of the path elements from the leaf to the root. 0 indicates that the element is on the right to the path, 1 indicates that the element is on the left to the path. The length of this vector is LEVELS
#[derive(Clone)]
pub struct MstInclusionCircuit<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> {
    pub entry: Entry<N_ASSETS>,
    pub path_element_hashes: Vec<Fp>,
    pub path_element_balances: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
    pub root_hash: Fp,
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> CircuitExt<Fp>
    for MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
    [usize; N_ASSETS + 1]: Sized,
{
    /// Returns the number of public inputs of the circuit. It is 2, namely the laef hash to be verified inclusion of and the root hash of the merkle sum tree.
    fn num_instance(&self) -> Vec<usize> {
        vec![2]
    }
    /// Returns the values of the public inputs of the circuit. Namely the leaf hash to be verified inclusion of and the root hash of the merkle sum tree.
    fn instances(&self) -> Vec<Vec<Fp>> {
        vec![vec![self.entry.compute_leaf().hash, self.root_hash]]
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> CircuitBase
    for MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
{
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
{
    pub fn init_empty() -> Self {
        Self {
            entry: Entry::init_empty(),
            path_element_hashes: vec![Fp::zero(); LEVELS],
            path_element_balances: vec![[Fp::zero(); N_ASSETS]; LEVELS],
            path_indices: vec![Fp::zero(); LEVELS],
            root_hash: Fp::zero(),
        }
    }

    /// Initializes the circuit with the merkle proof and the entry of the user of which the inclusion is to be verified.
    pub fn init(merkle_proof: MerkleProof<N_ASSETS, N_BYTES>, entry: Entry<N_ASSETS>) -> Self
    where
        [usize; N_ASSETS + 1]:,
    {
        assert_eq!(merkle_proof.path_indices.len(), LEVELS);
        assert_eq!(merkle_proof.sibling_hashes.len(), LEVELS);
        assert_eq!(merkle_proof.sibling_sums.len(), LEVELS);

        // assert that the entry leaf hash matches the leaf hash in the merkle proof
        assert_eq!(merkle_proof.leaf.hash, entry.compute_leaf().hash);

        Self {
            entry,
            path_element_hashes: merkle_proof.sibling_hashes,
            path_element_balances: merkle_proof.sibling_sums,
            path_indices: merkle_proof.path_indices,
            root_hash: merkle_proof.root_hash,
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
/// * `poseidon_entry_config`: Configuration for the poseidon hash function with WIDTH = 2 and RATE = 1 and input length of 1 + N_ASSETS. Needed to perform the hashing from the entry to the leaf.
/// * `poseidon_middle_config`: Configuration for the poseidon hash function with WIDTH = 2 and RATE = 1 and input length of 2 * (1 + N_ASSETS). Needed to perform hashings from the leaf to the root.
/// * `range_check_config`: Configuration for the range check chip
/// * `instance`: Instance column used to store the public inputs

#[derive(Debug, Clone)]
pub struct MstInclusionConfig<const N_ASSETS: usize, const N_BYTES: usize>
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    merkle_sum_tree_config: MerkleSumTreeConfig,
    poseidon_entry_config: PoseidonConfig<2, 1, { 1 + N_ASSETS }>,
    poseidon_middle_config: PoseidonConfig<2, 1, { 2 * (1 + N_ASSETS) }>,
    range_check_config: RangeCheckConfig<N_BYTES>,
    instance: Column<Instance>,
    advices: [Column<Advice>; 3],
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
        let enable_lookup_selector = meta.complex_selector();

        // enable constant for the fixed_column[2], this is required for the poseidon chip and the range check chip
        meta.enable_constant(fixed_columns[2]);

        let poseidon_entry_config = PoseidonChip::<PoseidonSpec, 2, 1, { 1 + N_ASSETS }>::configure(
            meta,
            advices[0..2].try_into().unwrap(),
            advices[2],
            fixed_columns[0..2].try_into().unwrap(),
            fixed_columns[2..4].try_into().unwrap(),
        );

        // in fact, the poseidon config requires #WIDTH advice columns for state and 1 for partial_sbox, #WIDTH fixed columns for rc_a and #WIDTH for rc_b
        let poseidon_middle_config =
            PoseidonChip::<PoseidonSpec, 2, 1, { 2 * (1 + N_ASSETS) }>::configure(
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
            enable_lookup_selector,
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            merkle_sum_tree_config,
            poseidon_entry_config,
            poseidon_middle_config,
            range_check_config,
            instance,
            advices,
        }
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

        let poseidon_entry_chip = PoseidonChip::<PoseidonSpec, 2, 1, { 1 + N_ASSETS }>::construct(
            config.poseidon_entry_config.clone(),
        );

        let poseidon_middle_chip =
            PoseidonChip::<PoseidonSpec, 2, 1, { 2 * (1 + N_ASSETS) }>::construct(
                config.poseidon_middle_config.clone(),
            );

        let range_check_chip = RangeCheckChip::<N_BYTES>::construct(config.range_check_config);

        // Assign the entry username
        let username = self.assign_value_to_witness(
            layouter.namespace(|| "assign entry username"),
            big_uint_to_fp(self.entry.username_as_big_uint()),
            "entry username",
            config.advices[0],
        )?;

        // Assign the entry balances
        let mut current_balances = vec![];

        for i in 0..N_ASSETS {
            let balance = self.assign_value_to_witness(
                layouter.namespace(|| format!("assign entry balance {}", i)),
                big_uint_to_fp(&self.entry.balances()[i]),
                "entry balance",
                config.advices[1],
            )?;
            current_balances.push(balance);
        }

        // Perform the hashing to username and balances to obtain the leaf hash
        // create an hash_input array of length 1 + N_ASSETS that contains the entry username and the entry balances
        let entry_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> = [username]
            .iter()
            .chain(current_balances.iter())
            .map(|x| x.to_owned())
            .collect();

        let entry_hasher_input: [AssignedCell<Fp, Fp>; 1 + N_ASSETS] =
            match entry_hasher_input_vec.try_into() {
                Ok(arr) => arr,
                Err(_) => panic!("Failed to convert Vec to Array"),
            };

        // compute the entry hash
        let mut current_hash = poseidon_entry_chip.hash(
            layouter.namespace(|| "perform poseidon entry hash"),
            entry_hasher_input,
        )?;

        // expose the first current hash, namely the leaf hash, as public input
        self.expose_public(
            layouter.namespace(|| "public leaf hash"),
            &current_hash,
            0,
            config.instance,
        )?;

        // load range check chip
        range_check_chip.load(&mut layouter)?;

        for level in 0..LEVELS {
            let namespace_prefix = format!("level {}", level);

            // For each level assign the index to the circuit
            let swap_bit_level = self.assign_value_to_witness(
                layouter.namespace(|| format!("{}: assign swap bit", namespace_prefix)),
                self.path_indices[level],
                "swap bit",
                config.advices[0],
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

            // create an hash_input array of length  2 * (1 + N_ASSETS)  that contains the left hash, the left balances, the right hash and the right balances
            let middle_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> = [hash_left_current]
                .iter()
                .chain(left_balances.iter())
                .chain([hash_right_current].iter())
                .chain(right_balances.iter())
                .map(|x| x.to_owned())
                .collect();

            let middle_hasher_input: [AssignedCell<Fp, Fp>; 2 * (1 + N_ASSETS)] =
                match middle_hasher_input_vec.try_into() {
                    Ok(arr) => arr,
                    Err(_) => panic!("Failed to convert Vec to Array"),
                };

            // compute the next hash
            let computed_hash = poseidon_middle_chip.hash(
                layouter.namespace(|| format!("{}: perform poseidon hash", namespace_prefix)),
                middle_hasher_input,
            )?;

            current_balances = next_balances;
            current_hash = computed_hash;
        }

        // expose the last current hash, namely the root hash, as public input
        self.expose_public(
            layouter.namespace(|| "public root hash"),
            &current_hash,
            1,
            config.instance,
        )?;

        // perform range check on the balances of the root to make sure these lie in the range defined by N_BYTES
        for balance in current_balances.iter() {
            range_check_chip.assign(layouter.namespace(|| "range check root balance"), balance)?;
        }

        Ok(())
    }
}
