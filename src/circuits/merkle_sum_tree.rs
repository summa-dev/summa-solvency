use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*};

#[derive(Default, Clone)]
pub struct MerkleSumTreeCircuit {
    pub leaf_hash: Fp,
    pub leaf_balance: Fp,
    pub path_element_hashes: Vec<Fp>,
    pub path_element_balances: Vec<Fp>,
    pub path_indices: Vec<Fp>,
    pub assets_sum: Fp,
    pub root_hash: Fp,
}

impl Circuit<Fp> for MerkleSumTreeCircuit {
    type Config = MerkleSumTreeConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let instance = meta.instance_column();

        MerkleSumTreeChip::configure(meta, instance)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = MerkleSumTreeChip::construct(config);
        let (leaf_hash, leaf_balance) = chip.assing_leaf_hash_and_balance(
            layouter.namespace(|| "assign leaf"),
            self.leaf_hash,
            self.leaf_balance,
        )?;

        chip.expose_public(layouter.namespace(|| "public leaf hash"), &leaf_hash, 0)?;
        chip.expose_public(
            layouter.namespace(|| "public leaf balance"),
            &leaf_balance,
            1,
        )?;

        // apply it for level 0 of the merkle tree
        // node cells passed as inputs are the leaf_hash cell and the leaf_balance cell
        let (mut next_hash, mut next_sum) = chip.merkle_prove_layer(
            layouter.namespace(|| format!("level {} merkle proof", 0)),
            &leaf_hash,
            &leaf_balance,
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

        chip.expose_public(layouter.namespace(|| "public root"), &next_hash, 2)?;
        Ok(())
    }
}
