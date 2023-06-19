// use crate::chips::merkle_sum_tree::{MerkleSumTreeChip, MerkleSumTreeConfig};
// use crate::merkle_sum_tree::MerkleSumTree;
// use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner};
// use halo2_proofs::halo2curves::bn256::Fr as Fp;
// use halo2_proofs::plonk::{Advice, Circuit, Column, ConstraintSystem, Error};
// use snark_verifier_sdk::CircuitExt;

// #[derive(Clone)]
// pub struct SolvencyCircuit<const MST_WIDTH: usize, const N_ASSETS: usize> {
//     pub left_node_hash: Fp,
//     pub left_node_balances: [Fp; N_ASSETS],
//     pub right_node_hash: Fp,
//     pub right_node_balances: [Fp; N_ASSETS],
//     pub assets_sum: [Fp; N_ASSETS],
//     pub root_hash: Fp,
// }

// impl<const MST_WIDTH: usize, const N_ASSETS: usize> CircuitExt<Fp>
//     for SolvencyCircuit<MST_WIDTH, N_ASSETS>
// {
//     fn num_instance(&self) -> Vec<usize> {
//         vec![1 + N_ASSETS] // root hash + assets sum
//     }

//     fn instances(&self) -> Vec<Vec<Fp>> {
//         let mut instances = vec![self.root_hash];
//         instances.extend(self.assets_sum);
//         vec![instances]
//     }
// }

// impl<const MST_WIDTH: usize, const N_ASSETS: usize> SolvencyCircuit<MST_WIDTH, N_ASSETS> {
//     pub fn init_empty() -> Self {
//         Self {
//             left_node_hash: Fp::zero(),
//             left_node_balances: [Fp::zero(); N_ASSETS],
//             right_node_hash: Fp::zero(),
//             right_node_balances: [Fp::zero(); N_ASSETS],
//             assets_sum: [Fp::zero(); N_ASSETS],
//             root_hash: Fp::zero(),
//         }
//     }

//     pub fn init(assets_sum: [Fp; N_ASSETS], path: &str) -> Self {
//         let merkle_sum_tree = MerkleSumTree::<N_ASSETS>::new(path).unwrap();

//         let (penultimate_node_left, penultimate_node_right) = merkle_sum_tree
//             .penultimate_level_data()
//             .expect("Failed to retrieve penultimate level data");

//         let root_hash = merkle_sum_tree.root().hash;

//         Self {
//             left_node_hash: penultimate_node_left.hash,
//             left_node_balances: penultimate_node_left.balances,
//             right_node_hash: penultimate_node_right.hash,
//             right_node_balances: penultimate_node_right.balances,
//             assets_sum,
//             root_hash,
//         }
//     }
// }

// impl<const MST_WIDTH: usize, const N_ASSETS: usize> Circuit<Fp>
//     for SolvencyCircuit<MST_WIDTH, N_ASSETS>
// {
//     type Config = MerkleSumTreeConfig<MST_WIDTH>;
//     type FloorPlanner = SimpleFloorPlanner;

//     fn without_witnesses(&self) -> Self {
//         Self::init_empty()
//     }

//     fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
//         let mut advice_cols: Vec<Column<Advice>> = Vec::with_capacity(MST_WIDTH);
//         for _ in 0..MST_WIDTH {
//             advice_cols.push(meta.advice_column());
//         }

//         let instance = meta.instance_column();

//         MerkleSumTreeChip::<MST_WIDTH, N_ASSETS>::configure(
//             meta,
//             advice_cols.try_into().unwrap(),
//             instance,
//         )
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<Fp>,
//     ) -> Result<(), Error> {
//         let chip = MerkleSumTreeChip::construct(config);

//         // assign the left node hash and balances to the circuit
//         let (left_hash_assinged, left_balances_assigned) = chip.assign_leaf_hash_and_balances(
//             layouter.namespace(|| "assign left node"),
//             self.left_node_hash,
//             &self.left_node_balances,
//         )?;

//         // hash it with the right node hash and balances
//         let (root_hash, root_balances) = chip.merkle_prove_layer(
//             layouter.namespace(|| "penultimate level merkle proof"),
//             &left_hash_assinged,
//             &left_balances_assigned,
//             self.right_node_hash,
//             self.right_node_balances,
//             Fp::from(0), // hardcoded to 0 as we don't need to swap the nodes
//         )?;

//         // enforce root balances to be less than the assets sum
//         chip.enforce_less_than(
//             layouter.namespace(|| "enforce less than"),
//             &root_balances,
//             1,
//         )?;

//         // expose root hash to the public
//         chip.expose_public(layouter.namespace(|| "public root"), &root_hash, 0)?;
//         Ok(())
//     }
// }
