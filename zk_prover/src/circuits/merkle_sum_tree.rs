use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::chips::overflow::overflow_check::{OverflowCheckConfig, OverflowChip};
use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::merkle_sum_tree::{big_int_to_fp, MerkleProof, MerkleSumTree};
use halo2_proofs::circuit::{AssignedCell, Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Instance};
use snark_verifier_sdk::CircuitExt;

const ACC_COLS: usize = 5;
const MAX_BITS: u8 = 8;
const WIDTH: usize = 7;
const RATE: usize = 6;

// LEVELS indicates the levels of the tree
// L is the length of the hasher input, namely 2 + (2 * N_ASSETS)
// N_ASSETS is the number of assets in the tree
#[derive(Clone)]
pub struct MstInclusionCircuit<const LEVELS: usize, const L: usize, const N_ASSETS: usize> {
    pub leaf_hash: Fp,
    pub leaf_balances: Vec<Fp>,
    pub path_element_hashes: Vec<Fp>,
    pub path_element_balances: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
    pub root_hash: Fp,
}

impl<const LEVELS: usize, const L: usize, const N_ASSETS: usize> CircuitExt<Fp>
    for MstInclusionCircuit<LEVELS, L, N_ASSETS>
{
    fn num_instance(&self) -> Vec<usize> {
        vec![2]
    }

    fn instances(&self) -> Vec<Vec<Fp>> {
        vec![vec![self.leaf_hash, self.root_hash]]
    }
}

impl<const LEVELS: usize, const L: usize, const N_ASSETS: usize>
    MstInclusionCircuit<LEVELS, L, N_ASSETS>
{
    pub fn init_empty() -> Self {
        assert_eq!((N_ASSETS * 2) + 2, L);

        Self {
            leaf_hash: Fp::zero(),
            leaf_balances: vec![Fp::zero(); N_ASSETS],
            path_element_hashes: vec![Fp::zero(); LEVELS],
            path_element_balances: vec![[Fp::zero(); N_ASSETS]; LEVELS],
            path_indices: vec![Fp::zero(); LEVELS],
            root_hash: Fp::zero(),
        }
    }

    pub fn init(path: &str, user_index: usize) -> Self {
        let merkle_sum_tree = MerkleSumTree::new(path).unwrap();

        let proof: MerkleProof<N_ASSETS> = merkle_sum_tree.generate_proof(user_index).unwrap();

        assert_eq!(proof.path_indices.len(), LEVELS);
        assert_eq!(proof.sibling_hashes.len(), LEVELS);
        assert_eq!(proof.sibling_sums.len(), LEVELS);

        Self {
            leaf_hash: proof.entry.compute_leaf().hash,
            leaf_balances: proof
                .entry
                .balances()
                .iter()
                .map(big_int_to_fp)
                .collect::<Vec<_>>(),
            path_element_hashes: proof.sibling_hashes,
            path_element_balances: proof.sibling_sums,
            path_indices: proof.path_indices,
            root_hash: proof.root_hash,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MstInclusionConfig<const L: usize, const N_ASSETS: usize> {
    pub merkle_sum_tree_config: MerkleSumTreeConfig,
    pub poseidon_config: PoseidonConfig<WIDTH, RATE, L>,
    pub overflow_check_config: OverflowCheckConfig<MAX_BITS, ACC_COLS>,
    pub instance: Column<Instance>,
}

impl<const L: usize, const N_ASSETS: usize> MstInclusionConfig<L, N_ASSETS> {
    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> Self {
        // the max number of advices columns needed is WIDTH + 1 given requirement of the poseidon config
        let advices: [Column<Advice>; WIDTH + 1] = std::array::from_fn(|_| meta.advice_column());

        // in fact, the poseidon config requires #WIDTH advice columns for state and 1 for partial_sbox
        let poseidon_config = PoseidonChip::<PoseidonSpec, WIDTH, RATE, L>::configure(
            meta,
            advices[0..WIDTH].try_into().unwrap(),
            advices[WIDTH],
        );

        // the configuration of merkle_sum_tree will always require 3 advices, no matter the number of assets
        let merkle_sum_tree_config =
            MerkleSumTreeChip::<N_ASSETS>::configure(meta, advices[0..3].try_into().unwrap());

        assert!(ACC_COLS <= advices.len());

        let overflow_check_config = OverflowChip::<MAX_BITS, ACC_COLS>::configure(
            meta,
            advices[0..ACC_COLS].try_into().unwrap(),
            advices[ACC_COLS + 1],
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            merkle_sum_tree_config,
            poseidon_config,
            overflow_check_config,
            instance,
        }
    }

    // Enforce copy constraint check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.instance, row)
    }
}

impl<const LEVELS: usize, const L: usize, const N_ASSETS: usize> Circuit<Fp>
    for MstInclusionCircuit<LEVELS, L, N_ASSETS>
{
    type Config = MstInclusionConfig<L, N_ASSETS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        MstInclusionConfig::<L, N_ASSETS>::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // build auxiliary chips
        let merkle_sum_tree_chip =
            MerkleSumTreeChip::<N_ASSETS>::construct(config.merkle_sum_tree_config.clone());
        let poseidon_chip =
            PoseidonChip::<PoseidonSpec, WIDTH, RATE, L>::construct(config.poseidon_config.clone());
        let overflow_check_chip = OverflowChip::construct(config.overflow_check_config.clone());

        // Assign the leaf hash and the leaf balances
        let (mut current_hash, mut current_balances) = merkle_sum_tree_chip
            .assign_leaf_hash_and_balances(
                layouter.namespace(|| "assign leaf hash and balances"),
                self.leaf_hash,
                &self.leaf_balances,
            )?;

        // expose the first current hash, namely the leaf hash, as public input
        config.expose_public(layouter.namespace(|| "public leaf hash"), &current_hash, 0)?;

        // load overflow check chip
        overflow_check_chip.load(&mut layouter)?;

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

                // Each balance cell is constrained to be less than the overflow limit
                overflow_check_chip.assign(
                    layouter.namespace(|| {
                        format!(
                            "{}: asset {}: overflow check left balance",
                            namespace_prefix, asset
                        )
                    }),
                    &left_balance,
                )?;
                overflow_check_chip.assign(
                    layouter.namespace(|| {
                        format!(
                            "{}: asset {}: overflow check right balance",
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

            let hash_input: [AssignedCell<Fp, Fp>; L] = match hash_input_vec.try_into() {
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

        // perform range check on the balances of the root node
        for balance in current_balances.iter() {
            overflow_check_chip.assign(
                layouter.namespace(|| "overflow check root balance"),
                balance,
            )?;
        }

        Ok(())
    }
}
