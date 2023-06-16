use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use crate::merkle_sum_tree::{big_int_to_fp, MerkleProof, MerkleSumTree};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};
use snark_verifier_sdk::CircuitExt;

#[derive(Clone)]
pub struct MerkleSumTreeCircuit<const LEVELS: usize, const MST_WIDTH: usize, const N_ASSETS: usize>
{
    pub leaf_hash: Fp,
    pub leaf_balances: Vec<Fp>,
    pub path_element_hashes: Vec<Fp>,
    pub path_element_balances: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
    pub assets_sum: Vec<Fp>,
    pub root_hash: Fp,
}

impl<const LEVELS: usize, const MST_WIDTH: usize, const N_ASSETS: usize> CircuitExt<Fp>
    for MerkleSumTreeCircuit<LEVELS, MST_WIDTH, N_ASSETS>
{
    fn num_instance(&self) -> Vec<usize> {
        vec![2 + N_ASSETS]
    }

    fn instances(&self) -> Vec<Vec<Fp>> {
        let mut instances = vec![self.leaf_hash];
        instances.push(self.root_hash);
        instances.extend(&self.assets_sum);
        vec![instances]
    }
}

impl<const LEVELS: usize, const MST_WIDTH: usize, const N_ASSETS: usize>
    MerkleSumTreeCircuit<LEVELS, MST_WIDTH, N_ASSETS>
{
    pub fn init_empty() -> Self {
        Self {
            leaf_hash: Fp::zero(),
            leaf_balances: vec![Fp::zero(); N_ASSETS],
            path_element_hashes: vec![Fp::zero(); LEVELS],
            path_element_balances: vec![[Fp::zero(); N_ASSETS]; LEVELS],
            path_indices: vec![Fp::zero(); LEVELS],
            assets_sum: vec![Fp::zero(); N_ASSETS],
            root_hash: Fp::zero(),
        }
    }

    pub fn init_from_assets_and_path(
        assets_sum: [Fp; N_ASSETS],
        path: &str,
        user_index: usize,
    ) -> Self {
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
            assets_sum: assets_sum.to_vec(),
            root_hash: proof.root_hash,
        }
    }
}

impl<const LEVELS: usize, const MST_WIDTH: usize, const N_ASSETS: usize> Circuit<Fp>
    for MerkleSumTreeCircuit<LEVELS, MST_WIDTH, N_ASSETS>
{
    type Config = MerkleSumTreeConfig<MST_WIDTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::init_empty()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        // Allocate MST_WIDTH of advice columns for the MerkleSumTreeChip
        let mut advice_cols: Vec<Column<Advice>> = Vec::with_capacity(MST_WIDTH);
        for _ in 0..MST_WIDTH {
            advice_cols.push(meta.advice_column());
        }

        let instance = meta.instance_column();

        MerkleSumTreeChip::<MST_WIDTH, N_ASSETS>::configure(
            meta,
            advice_cols.try_into().unwrap(),
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MerkleSumTreeChip::construct(config);
        let (leaf_hash, leaf_balances) = chip.assign_leaf_hash_and_balances(
            layouter.namespace(|| "assign leaf"),
            self.leaf_hash,
            &self.leaf_balances,
        )?;

        chip.expose_public(layouter.namespace(|| "public leaf hash"), &leaf_hash, 0)?;

        // apply it for level 0 of the merkle tree
        // node cells passed as inputs are the leaf_hash cell and the leaf_balance cell
        let (mut next_hash, mut next_sum) = chip.merkle_prove_layer(
            layouter.namespace(|| format!("level {} merkle proof", 0)),
            &leaf_hash,
            &leaf_balances,
            self.path_element_hashes[0],
            self.path_element_balances[0],
            self.path_indices[0],
        )?;

        // apply it for the remaining levels of the merkle tree
        // node cells passed as inputs are the computed_hash_prev_level cell and the computed_balance_prev_level cell
        for i in 1..self.path_element_balances.len() {
            (next_hash, next_sum) = chip.merkle_prove_layer(
                layouter.namespace(|| format!("level {} merkle proof", i)),
                &next_hash,
                &next_sum,
                self.path_element_hashes[i],
                self.path_element_balances[i],
                self.path_indices[i],
            )?;
        }

        // enforce computed sum to be less than the assets sum
        chip.enforce_less_than(layouter.namespace(|| "enforce less than"), &next_sum)?;

        chip.expose_public(
            layouter.namespace(|| "public root"),
            &next_hash,
            1,
        )?;
        Ok(())
    }
}
