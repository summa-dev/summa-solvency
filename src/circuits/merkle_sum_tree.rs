use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*};

#[derive(Clone)]
pub struct MerkleSumTreeCircuit<const MST_WIDTH: usize, const N_ASSETS: usize> {
    pub leaf_hash: Fp,
    pub leaf_balances: [Fp; N_ASSETS],
    pub path_element_hashes: Vec<Fp>,
    pub path_element_balances: Vec<[Fp; N_ASSETS]>,
    pub path_indices: Vec<Fp>,
    pub assets_sum: [Fp; N_ASSETS],
    pub root_hash: Fp,
}

impl<const MST_WIDTH: usize, const N_ASSETS: usize> Circuit<Fp>
    for MerkleSumTreeCircuit<MST_WIDTH, N_ASSETS>
{
    type Config = MerkleSumTreeConfig<MST_WIDTH>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        MerkleSumTreeCircuit::<MST_WIDTH, N_ASSETS> {
            leaf_hash: self.leaf_hash,
            leaf_balances: self.leaf_balances,
            path_element_hashes: vec![Fp::zero(); self.path_element_hashes.len()],
            path_element_balances: vec![[Fp::zero(); N_ASSETS]; self.path_element_balances.len()],
            path_indices: vec![Fp::zero(); self.path_indices.len()],
            assets_sum: [Fp::zero(); N_ASSETS],
            root_hash: Fp::zero(),
        }
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

        for (i, asset_balance) in leaf_balances.iter().enumerate() {
            chip.expose_public(
                layouter.namespace(|| "public leaf balance"),
                asset_balance,
                1 + i,
            )?;
        }

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
            1 + N_ASSETS,
        )?;
        Ok(())
    }
}
