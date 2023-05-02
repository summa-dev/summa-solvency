use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
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

        // enforce computed sum to be less than the assets sum 
        chip.enforce_less_than(layouter.namespace(|| "enforce less than"), &next_sum)?;

        chip.expose_public(layouter.namespace(|| "public root"), &next_hash, 2)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {

    use super::MerkleSumTreeCircuit;
    use halo2_proofs::{
        dev::{MockProver, FailureLocation, VerifyFailure}, 
        halo2curves::bn256::{Fr as Fp, Bn256},
        plonk::{Any, keygen_pk, keygen_vk},
        poly::{
            kzg::{
                commitment::{ParamsKZG},
            },
        },
    };
    use std::marker::PhantomData;
    use merkle_sum_tree_rust::{MerkleSumTree, MerkleProof};
    use super::super::utils::{full_prover, full_verifier};
    use rand::rngs::OsRng;

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

    fn instantiate_empty_circuit() -> MerkleSumTreeCircuit<Fp>{
        MerkleSumTreeCircuit {
            leaf_hash: Fp::zero(),
            leaf_balance: Fp::zero(),
            path_element_hashes: vec![Fp::zero(); 4],
            path_element_balances: vec![Fp::zero(); 4],
            path_indices: vec![Fp::zero(); 4],
            assets_sum : Fp::zero(),
            root_hash: Fp::zero(),
            _marker: PhantomData,
        }
    }

    #[test]
    fn test_valid_merkle_sum_tree() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_circuit(assets_sum);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        let valid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();

        valid_prover.assert_satisfied();

    }

    #[test]
    fn test_valid_merkle_sum_tree_with_full_prover() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_empty_circuit();

        // we generate a universal trusted setup of our own for testing
        let params = ParamsKZG::<Bn256>::setup(8, OsRng);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        // Note: the dimension of the circuit used to generate the keys must be the same as the dimension of the circuit used to generate the proof
        // In this case, the dimension are represented by the heigth of the merkle tree
        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = instantiate_circuit(assets_sum);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, &public_input);

        // verify the proof to be true
        assert!(full_verifier(&params, &vk, proof, &public_input));
    }

    // Passing an invalid root hash in the instance column should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_root_hash() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_circuit(assets_sum);

        let invalid_root_hash = Fp::from(1000u64);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, invalid_root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(9, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 2 } },
                VerifyFailure::Permutation { column: (Any::advice(), 5).into(), location: FailureLocation::InRegion {
                    region: (16, "permute state").into(),
                    offset: 36
                    }
                }
            ])
        );

    }

    #[test]
    fn test_invalid_root_hash_with_full_prover() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_empty_circuit();

        // we generate a universal trusted setup of our own for testing
        let params = ParamsKZG::<Bn256>::setup(8, OsRng);

        // we generate the verification key and the proving key
        // we use an empty circuit just to enphasize that the circuit input are not relevant when generating the keys
        let vk = keygen_vk(&params, &circuit).expect("vk should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let circuit = instantiate_circuit(assets_sum);

        let invalid_root_hash = Fp::from(1000u64);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, invalid_root_hash, circuit.assets_sum];

        // Generate the proof
        let proof = full_prover(&params, &pk, circuit, &public_input);

        // verify the proof to be false
        assert!(!full_verifier(&params, &vk, proof, &public_input));

    }

    // Passing an invalid leaf hash as input for the witness generation should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_hash_as_witness() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let mut circuit = instantiate_circuit(assets_sum);

        // invalidate leaf hash
        circuit.leaf_hash = Fp::from(1000u64);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 2 } },
                VerifyFailure::Permutation { column: (Any::advice(), 5).into(), location: FailureLocation::InRegion {
                    region: (16, "permute state").into(),
                    offset: 36
                    }
                }
            ])
        );
    }

    // Passing an invalid leaf hash in the instance column should fail the permutation check between the (valid) leaf hash added as part of the witness and the instance column leaf hash
    #[test]
    fn test_invalid_leaf_hash_as_instance() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_circuit(assets_sum);

        // add invalid leaf hash in the instance column
        let invalid_leaf_hash = Fp::from(1000u64);

        let public_input = vec![invalid_leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation { column: (Any::advice(), 0).into(), location: FailureLocation::InRegion {
                    region: (1, "merkle prove layer").into(),
                    offset: 0
                    }
                },
                VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 0 } },
            ])
        );
    }

    // Passing an invalid leaf balance as input for the witness generation should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_invalid_leaf_balance_as_witness() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let user_balance = Fp::from(11888u64);

        let mut circuit = instantiate_circuit(assets_sum);

        // invalid leaf balance
        circuit.leaf_hash = Fp::from(1000u64);

        let public_input = vec![circuit.leaf_hash, user_balance, circuit.root_hash, assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 2 } },
                VerifyFailure::Permutation { column: (Any::advice(), 5).into(), location: FailureLocation::InRegion {
                    region: (16, "permute state").into(),
                    offset: 36
                    }
                }
            ])
        );
    }
    

    // Passing an invalid leaf balance in the instance column should fail the permutation check between the (valid) leaf balance added as part of the witness and the instance column leaf balance
    #[test]
    fn test_invalid_leaf_balance_as_instance() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_circuit(assets_sum);

        // add invalid leaf balance in the instance column
        let invalid_leaf_balance = Fp::from(1000u64);

        let public_input = vec![circuit.leaf_hash, invalid_leaf_balance, circuit.root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation { column: (Any::advice(), 1).into(), location: FailureLocation::InRegion {
                    region: (1, "merkle prove layer").into(),
                    offset: 0
                    }
                },
                VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 1 } },
            ])
        );
    }

    // Passing a non binary index should fail the bool constraint check, the two swap constraints and the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_non_binary_index() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let mut circuit = instantiate_circuit(assets_sum);

        // invalidate path index inside the circuit
        circuit.path_indices[0] = Fp::from(2);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
            VerifyFailure::ConstraintNotSatisfied {
                constraint: ((0, "bool constraint").into(), 0, "").into(),
                location: FailureLocation::InRegion {
                    region: (1, "merkle prove layer").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 4).into(), 0).into(), "0x2".to_string()),
                    ]
            },
            VerifyFailure::ConstraintNotSatisfied {
                constraint: ((1, "swap constraint").into(), 0, "").into(),
                location: FailureLocation::InRegion {
                    region: (1, "merkle prove layer").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 0).into(), 0).into(), "0x221a31fb6a7dfe98cfeca9b0a78061056f42f31f5d5719cfbc5c8110e38ed0b0".to_string()),
                    (((Any::advice(), 0).into(), 1).into(), "0x17063e69d8505e34b85820ae85ed171e8a44f82aefdcceec66397495e3286b6a".to_string()),
                    (((Any::advice(), 2).into(), 0).into(), "0x17063e69d8505e34b85820ae85ed171e8a44f82aefdcceec66397495e3286b6a".to_string()),
                    (((Any::advice(), 2).into(), 1).into(), "0x221a31fb6a7dfe98cfeca9b0a78061056f42f31f5d5719cfbc5c8110e38ed0b0".to_string()),
                    (((Any::advice(), 4).into(), 0).into(), "0x2".to_string()),
                    ]
            },
            VerifyFailure::ConstraintNotSatisfied {
                constraint: ((1, "swap constraint").into(), 1, "").into(),
                location: FailureLocation::InRegion {
                    region: (1, "merkle prove layer").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 1).into(), 0).into(), "0x2e70".to_string()),
                    (((Any::advice(), 1).into(), 1).into(), "0x108ef".to_string()),
                    (((Any::advice(), 3).into(), 0).into(), "0x108ef".to_string()),
                    (((Any::advice(), 3).into(), 1).into(), "0x2e70".to_string()),
                    (((Any::advice(), 4).into(), 0).into(), "0x2".to_string()),
                    ]
            }, 
            VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 2 } },
            VerifyFailure::Permutation { column: (Any::advice(), 5).into(), location: FailureLocation::InRegion {
                region: (16, "permute state").into(),
                offset: 36
                }
            }
            ])
        );
    }

    // Swapping the indices should fail the permutation check between the computed root hash and the instance column root hash
    #[test]
    fn test_swapping_index() {

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let mut circuit = instantiate_circuit(assets_sum);

        // swap indices
        circuit.path_indices[0] = Fp::from(1);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation { column: (Any::Instance, 0).into(), location: FailureLocation::OutsideRegion { row: 2 } },
                VerifyFailure::Permutation { column: (Any::advice(), 5).into(), location: FailureLocation::InRegion {
                    region: (16, "permute state").into(),
                    offset: 36
                    }
                }
            ])
        );
    }

    // Passing an assets sum that is less than the liabilities sum should fail the lessThan constraint check
    #[test]
    fn test_is_not_less_than() {

        let less_than_assets_sum = Fp::from(556861u64); // less than liabilities sum (556862)

        let circuit = instantiate_circuit(less_than_assets_sum);

        let public_input = vec![circuit.leaf_hash, circuit.leaf_balance, circuit.root_hash, circuit.assets_sum];

        let invalid_prover = MockProver::run(8, &circuit, vec![public_input]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::ConstraintNotSatisfied {
                constraint: ((7, "verifies that `check` from current config equal to is_lt from LtChip").into(), 0, "").into(),
                location: FailureLocation::InRegion {
                    region: (17, "enforce sum to be less than total assets").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 2).into(), 0).into(), "1".to_string()),
                    // The zero means that is not less than
                    (((Any::advice(), 11).into(), 0).into(), "0".to_string())
                    ]
            }
            ])
        );

        assert!(invalid_prover.verify().is_err());
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_merkle_sum_tree() {
        use plotters::prelude::*;

        let assets_sum = Fp::from(556863u64); // greater than liabilities sum (556862)

        let circuit = instantiate_circuit(assets_sum);

        let root =
            BitMapBackend::new("prints/merkle-sum-tree-layout.png", (2048, 16384)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("Merkle Sum Tree Layout", ("sans-serif", 60))
            .unwrap();

        halo2_proofs::dev::CircuitLayout::default()
            .render(8, &circuit, &root)
            .unwrap();
    }
}