use super::super::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
use halo2_proofs::{circuit::*, plonk::*};
use std::marker::PhantomData;
use eth_types::Field;

#[derive(Default)]
pub struct MerkleSumTreeCircuit <F: Field> {
    pub leaf_hash: F,
    pub leaf_balance: F,
    pub path_element_hashes: Vec<F>,
    pub path_element_balances: Vec<F>,
    pub path_indices: Vec<F>,
    pub assets_sum: F,
    pub root_hash: F,
    pub _marker: PhantomData<F>
}

impl <F:Field> Circuit<F> for MerkleSumTreeCircuit<F> {

    type Config = MerkleSumTreeConfig<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {

        // config columns for the merkle tree chip
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let col_d = meta.advice_column();
        let col_e = meta.advice_column();

        let instance = meta.instance_column();

        MerkleSumTreeChip::configure(
            meta,
            [col_a, col_b, col_c, col_d, col_e],
            instance,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {

        let chip = MerkleSumTreeChip::construct(config);
        let (leaf_hash, leaf_balance) = chip.assing_leaf_hash_and_balance(layouter.namespace(|| "assign leaf"), self.leaf_hash, self.leaf_balance)?;

        chip.expose_public(layouter.namespace(|| "public leaf hash"), &leaf_hash, 0)?;
        chip.expose_public(layouter.namespace(|| "public leaf balance"), &leaf_balance, 1)?;

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

        // compute the sum of the merkle sum tree as sum of the leaf balance and the sum of the path elements balances
        let computed_sum = self.leaf_balance + self.path_element_balances.iter().fold(F::zero(), |acc, x| acc + x);

        // enforce computed sum to be less than the assets sum 
        chip.enforce_less_than(layouter.namespace(|| "enforce less than"), &next_sum, computed_sum, self.assets_sum)?;

        chip.expose_public(layouter.namespace(|| "public root"), &next_hash, 2)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::MerkleSumTreeCircuit;
    use halo2_proofs::{
        dev::{MockProver, VerifyFailure, FailureLocation}, 
        halo2curves::bn256::{Fr as Fp},
        plonk::{Any},
    };
    use std::marker::PhantomData;
    use merkle_sum_tree_rust::{MerkleSumTree, MerkleProof};

    fn instantiate_circuit(assets_sum: Fp) -> MerkleSumTreeCircuit<Fp>{

        let merkle_sum_tree= MerkleSumTree::new("csv_entries/entry_16.csv").unwrap();

        let proof: MerkleProof = merkle_sum_tree.generate_proof(0).unwrap();

        MerkleSumTreeCircuit {
            leaf_hash: proof.entry.compute_leaf().hash,
            leaf_balance: Fp::from(proof.entry.balance()),
            path_element_hashes: proof.sibling_hashes,
            path_element_balances: proof.sibling_sums,
            path_indices: proof.path_indices,
            assets_sum,
            root_hash: proof.root_hash,
            _marker: PhantomData,
        }

    }

    #[test]
    fn test_valid_merkle_sum_tree() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let circuit = instantiate_circuit(assets_sum);

        let public_input = vec![circuit.leaf_hash, user_balance, circuit.root_hash, assets_sum];

        let valid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        valid_prover.assert_satisfied();

    }

    #[test]
    fn test_invalid_root_hash() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let circuit = instantiate_circuit(assets_sum);

        let public_input = vec![circuit.leaf_hash, user_balance, Fp::from(1000u64), assets_sum];

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        let result = invalid_prover.verify();

        let error = result.unwrap_err();

        let expected_error = "[Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 2), Equality constraint not satisfied by cell (Column('Advice', 5 - ), in Region 16 ('permute state') at offset 36)]";

        assert_eq!(format!("{:?}", error), expected_error);
    }

    #[test]
    fn test_invalid_leaf_hash() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let circuit = instantiate_circuit(assets_sum);

        let public_input = vec![Fp::from(1000u64), user_balance, circuit.root_hash, assets_sum];

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        let result = invalid_prover.verify();

        let error = result.unwrap_err();
        let expected_error = "[Equality constraint not satisfied by cell (Column('Advice', 0 - ), in Region 1 ('merkle prove layer') at offset 0), Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 0)]";

        assert_eq!(format!("{:?}", error), expected_error);

    }

    #[test]
    fn test_invalid_leaf_balance() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let invalid_user_balance = Fp::from(11887u64);

        let circuit = instantiate_circuit(assets_sum);

        let public_input = vec![circuit.leaf_hash, invalid_user_balance, circuit.root_hash, assets_sum];

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        let result = invalid_prover.verify();

        let error = result.unwrap_err();
        let expected_error = "[Equality constraint not satisfied by cell (Column('Advice', 1 - ), in Region 1 ('merkle prove layer') at offset 0), Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 1)]";

        assert_eq!(format!("{:?}", error), expected_error);
    }

    #[test]
    fn test_non_binary_index() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let mut circuit = instantiate_circuit(assets_sum);

        circuit.path_indices[0] = Fp::from(2);

        let public_input = vec![circuit.leaf_hash, user_balance, circuit.root_hash, assets_sum];

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error: constraint not satisfied 'bool constraint'
        // error: constraint not satisfied 'swap constraint'
        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_swapping_index() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let mut circuit = instantiate_circuit(assets_sum);

        // swap indices
        circuit.path_indices[0] = Fp::from(1);

        let public_input = vec![circuit.leaf_hash, user_balance, circuit.root_hash, assets_sum];

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();
        // error => Err([Equality constraint not satisfied by cell (Column('Instance', 0 - ), outside any region, on row 2), Equality constraint not satisfied by cell (Column('Advice', 5 - ), in Region 26 ('permute state') at offset 36)])
        // computed_hash (advice column[5]) != root.hash (instance column row 2)
        assert!(invalid_prover.verify().is_err());
    }

    #[test]
    fn test_is_not_less_than() {

        let less_than_assets_sum = Fp::from(556861u64); // less than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let circuit = instantiate_circuit(less_than_assets_sum);

        let public_input = vec![circuit.leaf_hash, user_balance, circuit.root_hash, less_than_assets_sum];

        let invalid_prover = MockProver::run(10, &circuit, vec![public_input]).unwrap();

        // error: constraint not satisfied
        //   Cell layout in region 'enforce sum to be less than total assets':
        //     | Offset | A2 | A11|
        //     +--------+----+----+
        //     |    0   | x0 | x1 | <--{ Gate 'verifies that `check` from current config equal to is_lt from LtChip ' applied here

        //   Constraint '':
        //     ((S10 * (1 - S10)) * (0x2 - S10)) * (x1 - x0) = 0

        //   Assigned cell values:
        //     x0 = 1
        //     x1 = 0
        assert!(invalid_prover.verify().is_err());
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_merkle_sum_tree() {
        use plotters::prelude::*;

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let circuit = instantiate_circuit(assets_sum);

        let root =
            BitMapBackend::new("prints/merkle-sum-tree-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(8, &circuit, &root)
            .unwrap();
    }
}