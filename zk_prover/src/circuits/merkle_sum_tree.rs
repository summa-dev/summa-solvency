use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::chips::range::range_check::{RangeCheckChip, RangeCheckConfig};
use crate::circuits::traits::CircuitBase;
use crate::merkle_sum_tree::{big_uint_to_fp, Entry, MerkleProof, Node};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{
    Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector,
};
use snark_verifier_sdk::CircuitExt;

/// Circuit for verifying inclusion of an entry (username, balances) inside a merkle sum tree with a given root.
///
/// # Type Parameters
///
/// * `LEVELS`: The number of levels of the merkle sum tree
/// * `N_ASSETS`: The number of assets for which the solvency is verified.
/// * `N_BYTES`: The number of bytes in which the balances should lie
///
/// # Fields
///
/// * `merkle_proof`: Merkle Proof of the entry to be verified inclusion of
#[derive(Clone)]
pub struct MstInclusionCircuit<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
    pub merkle_proof: MerkleProof<N_ASSETS, N_BYTES>,
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> CircuitExt<Fp>
    for MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
    /// Returns the number of public inputs of the circuit. It is {2 + N_ASSETS}, namely the leaf hash to be verified inclusion of, the root hash of the merkle sum tree and the root balances of the merkle sum tree.
    fn num_instance(&self) -> Vec<usize> {
        vec![{ 2 + N_ASSETS }]
    }
    /// Returns the values of the public inputs of the circuit. Namely the leaf hash to be verified inclusion of and the root hash of the merkle sum tree.
    fn instances(&self) -> Vec<Vec<Fp>> {
        let mut instance = vec![
            self.merkle_proof.entry.compute_leaf().hash,
            self.merkle_proof.root.hash,
        ];
        instance.extend_from_slice(&self.merkle_proof.root.balances);
        vec![instance]
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> CircuitBase
    for MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    MstInclusionCircuit<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
    pub fn init_empty() -> Self {
        Self {
            merkle_proof: MerkleProof::init_empty(),
        }
    }

    /// Initializes the circuit with the merkle proof and the entry of the user of which the inclusion is to be verified.
    pub fn init(merkle_proof: MerkleProof<N_ASSETS, N_BYTES>) -> Self
    where
        [usize; N_ASSETS + 1]: Sized,
        [usize; N_ASSETS + 2]: Sized,
    {
        assert_eq!(merkle_proof.path_indices.len(), LEVELS);
        assert_eq!(
            merkle_proof.sibling_middle_node_hash_preimages.len(),
            LEVELS - 1
        );
        Self { merkle_proof }
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
/// * `advices`: Advice columns used to store the private inputs

#[derive(Debug, Clone)]
pub struct MstInclusionConfig<const N_ASSETS: usize, const N_BYTES: usize>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
{
    merkle_sum_tree_config: MerkleSumTreeConfig,
    poseidon_entry_config: PoseidonConfig<2, 1, { N_ASSETS + 1 }>,
    poseidon_middle_config: PoseidonConfig<2, 1, { N_ASSETS + 2 }>,
    range_check_config: RangeCheckConfig<N_BYTES>,
    instance: Column<Instance>,
    advices: [Column<Advice>; 3],
}

impl<const N_ASSETS: usize, const N_BYTES: usize> MstInclusionConfig<N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
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

        let poseidon_entry_config = PoseidonChip::<PoseidonSpec, 2, 1, { N_ASSETS + 1 }>::configure(
            meta,
            advices[0..2].try_into().unwrap(),
            advices[2],
            fixed_columns[0..2].try_into().unwrap(),
            fixed_columns[2..4].try_into().unwrap(),
        );

        // in fact, the poseidon config requires #WIDTH advice columns for state and 1 for partial_sbox, #WIDTH fixed columns for rc_a and #WIDTH for rc_b
        let poseidon_middle_config =
            PoseidonChip::<PoseidonSpec, 2, 1, { N_ASSETS + 2 }>::configure(
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
    [usize; N_ASSETS + 1]: Sized,
    [usize; N_ASSETS + 2]: Sized,
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
            MerkleSumTreeChip::<N_ASSETS>::construct(config.merkle_sum_tree_config);

        let poseidon_entry_chip = PoseidonChip::<PoseidonSpec, 2, 1, { N_ASSETS + 1 }>::construct(
            config.poseidon_entry_config,
        );

        let poseidon_middle_chip = PoseidonChip::<PoseidonSpec, 2, 1, { N_ASSETS + 2 }>::construct(
            config.poseidon_middle_config,
        );

        let range_check_chip = RangeCheckChip::<N_BYTES>::construct(config.range_check_config);

        // Assign the entry username to the witness
        let username = self.assign_value_to_witness(
            layouter.namespace(|| "assign entry username"),
            big_uint_to_fp(self.merkle_proof.entry.username_as_big_uint()),
            "entry username",
            config.advices[0],
        )?;

        // Assign the entry balances to the witness
        let mut current_balances = vec![];

        for i in 0..N_ASSETS {
            let balance = self.assign_value_to_witness(
                layouter.namespace(|| format!("assign entry balance {}", i)),
                big_uint_to_fp(&self.merkle_proof.entry.balances()[i]),
                "entry balance",
                config.advices[1],
            )?;
            current_balances.push(balance);
        }

        // Perform the hashing to username and balances to obtain the leaf hash
        // create an hash_input array of length N_ASSETS + 1 that contains the entry username and the entry balances
        let entry_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> = [username]
            .iter()
            .chain(current_balances.iter())
            .map(|x| x.to_owned())
            .collect();

        let entry_hasher_input: [AssignedCell<Fp, Fp>; N_ASSETS + 1] =
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

            let sibling_hash: AssignedCell<Fp, Fp>; // hash of the sibling node
            let mut sibling_balances: Vec<AssignedCell<Fp, Fp>> = vec![]; // balances of the sibling node

            // Perform the hashing of sibling leaf hash preimage to obtain the sibling leaf hash
            if level == 0 {
                // Assign username from sibling leaf node hash preimage to the circuit
                let sibling_leaf_node_username = self.assign_value_to_witness(
                    layouter.namespace(|| format!("sibling leaf node username")),
                    self.merkle_proof.sibling_leaf_node_hash_preimage[0],
                    "sibling leaf node username",
                    config.advices[0],
                )?;

                // Assign balances from sibling leaf node hash preimage to the circuit
                for asset in 0..N_ASSETS {
                    let leaf_node_sibling_balance = self.assign_value_to_witness(
                        layouter.namespace(|| format!("sibling leaf node balance {}", asset)),
                        self.merkle_proof.sibling_leaf_node_hash_preimage[asset + 1],
                        "sibling leaf balance",
                        config.advices[1],
                    )?;
                    sibling_balances.push(leaf_node_sibling_balance);
                }

                // create an hash_input array of length N_ASSETS + 1 that contains the sibling_leaf_node_username and the sibling_balances (the sibling leaf node hash preimage)
                let sibling_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> =
                    [sibling_leaf_node_username]
                        .iter()
                        .chain(sibling_balances.iter())
                        .map(|x| x.to_owned())
                        .collect();

                let sibling_hasher_input: [AssignedCell<Fp, Fp>; N_ASSETS + 1] =
                    match sibling_hasher_input_vec.try_into() {
                        Ok(arr) => arr,
                        Err(_) => panic!("Failed to convert Vec to Array"),
                    };

                // compute the sibling hash
                let computed_sibling_hash = poseidon_entry_chip.hash(
                    layouter.namespace(|| format!("{}: perform poseidon hash", namespace_prefix)),
                    sibling_hasher_input,
                )?;

                sibling_hash = computed_sibling_hash;
            }
            // Other levels
            // Assign sibling node hash preimage to the circuit (split it in balances, left child hash and right child hash)
            // Perform the hashing of sibling node hash preimage to obtain the sibling node hash
            else {
                // Assign balances from sibling middle node hash preimage to the circuit
                for asset in 0..N_ASSETS {
                    let middle_node_sibling_balance = self.assign_value_to_witness(
                        layouter.namespace(|| format!("sibling node balance {}", asset)),
                        self.merkle_proof.sibling_middle_node_hash_preimages[level - 1][asset],
                        "sibling node balance",
                        config.advices[1],
                    )?;
                    sibling_balances.push(middle_node_sibling_balance);
                }

                // Assign middle_node_sibling_child_left_hash from middle node hash preimage to the circuit
                let middle_node_sibling_child_left_hash = self.assign_value_to_witness(
                    layouter.namespace(|| format!("sibling left hash")),
                    self.merkle_proof.sibling_middle_node_hash_preimages[level - 1][N_ASSETS],
                    "sibling left hash",
                    config.advices[2],
                )?;

                // Assign middle_node_sibling_child_right_hash from middle node hash preimage to the circuit
                let middle_node_sibling_child_right_hash = self.assign_value_to_witness(
                    layouter.namespace(|| format!("sibling right hash")),
                    self.merkle_proof.sibling_middle_node_hash_preimages[level - 1][N_ASSETS + 1],
                    "sibling right hash",
                    config.advices[2],
                )?;

                // create an hash_input array of length 2 + N_ASSETS that contains the sibling balances, the middle_node_sibling_child_left_hash and the middle_node_sibling_child_right_hash
                let sibling_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> = sibling_balances
                    .iter()
                    .chain([middle_node_sibling_child_left_hash].iter())
                    .chain([middle_node_sibling_child_right_hash].iter())
                    .map(|x| x.to_owned())
                    .collect();

                let sibling_hasher_input: [AssignedCell<Fp, Fp>; N_ASSETS + 2] =
                    match sibling_hasher_input_vec.try_into() {
                        Ok(arr) => arr,
                        Err(_) => panic!("Failed to convert Vec to Array"),
                    };

                // compute the sibling hash
                let computed_sibling_hash = poseidon_middle_chip.hash(
                    layouter.namespace(|| format!("{}: perform poseidon hash", namespace_prefix)),
                    sibling_hasher_input,
                )?;

                sibling_hash = computed_sibling_hash;
            };

            // For each level assign the swap bit to the circuit
            let swap_bit_level = self.assign_value_to_witness(
                layouter.namespace(|| format!("{}: assign swap bit", namespace_prefix)),
                self.merkle_proof.path_indices[level],
                "swap bit",
                config.advices[0],
            )?;

            // For every level, perform the swap of the hashes (between `current_hash` and `sibling_hash`) according to the swap bit
            let (hash_left_current, hash_right_current) = merkle_sum_tree_chip
                .swap_hashes_per_level(
                    layouter.namespace(|| format!("{}: swap hashes", namespace_prefix)),
                    &current_hash,
                    &sibling_hash,
                    &swap_bit_level,
                )?;

            let mut next_balances = vec![];
            let mut left_balances = vec![];
            let mut right_balances = vec![];

            // For every level, perform the swap of the balances (between `current_balances` and `sibling_balances`) according to the swap bit
            for asset in 0..N_ASSETS {
                let (left_balance, right_balance, next_balance) = merkle_sum_tree_chip
                    .swap_balances_per_level(
                        layouter.namespace(|| {
                            format!(
                                "{}: asset {}: assign nodes balance",
                                namespace_prefix, asset
                            )
                        }),
                        &current_balances[asset],
                        &sibling_balances[asset],
                        &swap_bit_level,
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

            // create an hash_input array of length N_ASSETS + 2 that contains the next balances, the left hash and the right hash
            let middle_hasher_input_vec: Vec<AssignedCell<Fp, Fp>> = next_balances
                .iter()
                .chain([hash_left_current].iter())
                .chain([hash_right_current].iter())
                .map(|x| x.to_owned())
                .collect();

            let middle_hasher_input: [AssignedCell<Fp, Fp>; N_ASSETS + 2] =
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

        // expose the last current balances, namely the root balances, as public input
        for (i, balance) in current_balances.iter().enumerate() {
            self.expose_public(
                layouter.namespace(|| format!("public root balance {}", i)),
                balance,
                2 + i,
                config.instance,
            )?;
        }

        // perform range check on the balances of the root to make sure these lie in the range defined by N_BYTES
        for balance in current_balances.iter() {
            range_check_chip.assign(layouter.namespace(|| "range check root balance"), balance)?;
        }

        Ok(())
    }
}
