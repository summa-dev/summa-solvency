use crate::chips::poseidon::hash::{PoseidonChip, PoseidonConfig};
use crate::chips::poseidon::spec_node::MySpec as PoseidonSpecNode;
use crate::merkle_sum_tree::{R_L_NODE, WIDTH_NODE};
use gadgets::less_than::{LtChip, LtConfig, LtInstruction};
use halo2_gadgets::utilities::FieldValue;
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};

const WIDTH: usize = WIDTH_NODE;
const RATE: usize = R_L_NODE;
const L: usize = R_L_NODE;

#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig<const MST_WIDTH: usize> {
    pub advice: [Column<Advice>; MST_WIDTH],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub sum_selector: Selector,
    pub lt_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<WIDTH, RATE, L>,
    pub lt_configs: Vec<LtConfig<Fp, 8>>,
}
#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip<const MST_WIDTH: usize, const N_ASSETS: usize> {
    config: MerkleSumTreeConfig<MST_WIDTH>,
}

impl<const MST_WIDTH: usize, const N_ASSETS: usize> MerkleSumTreeChip<MST_WIDTH, N_ASSETS> {
    pub fn construct(config: MerkleSumTreeConfig<MST_WIDTH>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; MST_WIDTH],
        instance: Column<Instance>,
    ) -> MerkleSumTreeConfig<MST_WIDTH> {
        let col_a: Column<Advice> = advice[advice.len() - 3];
        let col_b: Column<Advice> = advice[advice.len() - 2];
        let col_c: Column<Advice> = advice[advice.len() - 1];

        // create selectors
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let sum_selector = meta.selector();
        let lt_selector = meta.selector();

        // enable equality for leaf hashes, balances and computed sums copy constraint with instance column (col_a)
        for col in advice.iter() {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        // Enforces that swap_bit is either a 0 or 1 when the bool selector is enabled
        // s * swap_bit * (1 - swap_bit) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let swap_bit = meta.query_advice(col_c, Rotation::cur());
            vec![s * swap_bit.clone() * (Expression::Constant(Fp::from(1)) - swap_bit)]
        });

        // Enforces that if the swap_bit is on, the columns will be swapped.
        // This applies only when the swap selector is enabled
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let swap_bit = meta.query_advice(col_c, Rotation::cur());
            let hash_l_cur = meta.query_advice(col_a, Rotation::cur());
            let hash_r_cur = meta.query_advice(col_b, Rotation::cur());
            let hash_l_next = meta.query_advice(col_a, Rotation::next());
            let hash_r_next = meta.query_advice(col_b, Rotation::next());

            let hashes_constraint = s.clone()
                * swap_bit.clone()
                * ((hash_l_next - hash_l_cur) - (hash_r_cur - hash_r_next));

            //Element-wise balance constraints for the sibling nodes
            let balance_constraints = (0..N_ASSETS)
                .map(|i| {
                    let balance_l_cur = meta.query_advice(advice[i], Rotation::cur());
                    let balance_r_cur = meta.query_advice(advice[i + N_ASSETS], Rotation::cur());
                    let balance_l_next = meta.query_advice(advice[i], Rotation::next());
                    let balance_r_next = meta.query_advice(advice[i + N_ASSETS], Rotation::next());

                    s.clone()
                        * swap_bit.clone()
                        * ((balance_l_next - balance_l_cur) - (balance_r_cur - balance_r_next))
                })
                .collect::<Vec<_>>();

            vec![hashes_constraint]
                .into_iter()
                .chain(balance_constraints)
                .collect::<Vec<_>>()
        });

        // Enforces that input_left_balance[i] + input_right_balance[i] = computed_sum[i]
        meta.create_gate("sum constraint", |meta| {
            (0..N_ASSETS)
                .map(|i| {
                    let left_balance = meta.query_advice(advice[i], Rotation::cur());
                    let right_balance = meta.query_advice(advice[i + N_ASSETS], Rotation::cur());
                    let computed_sum = meta.query_advice(advice[i + 2 * N_ASSETS], Rotation::cur());
                    let s = meta.query_selector(sum_selector);
                    s * (left_balance + right_balance - computed_sum)
                })
                .collect::<Vec<_>>()
        });

        let advice_columns_poseidon_chip = (0..WIDTH_NODE)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>();

        let poseidon_config =
            PoseidonChip::<PoseidonSpecNode, WIDTH_NODE, R_L_NODE, R_L_NODE>::configure(
                meta,
                &advice_columns_poseidon_chip,
            );

        // configure lt chips
        let mut lt_configs = Vec::with_capacity(N_ASSETS);
        for i in 0..N_ASSETS {
            lt_configs.push(LtChip::configure(
                meta,
                |meta| meta.query_selector(lt_selector),
                |meta| meta.query_advice(advice[i], Rotation::cur()),
                |meta| meta.query_advice(advice[i + N_ASSETS], Rotation::cur()),
            ));
        }

        let config = MerkleSumTreeConfig::<MST_WIDTH> {
            advice,
            bool_selector,
            swap_selector,
            sum_selector,
            lt_selector,
            instance,
            poseidon_config,
            lt_configs,
        };

        meta.create_gate(
            "verifies that `check` from current config equal to is_lt from LtChip",
            |meta| {
                (0..N_ASSETS)
                    .map(|i| {
                        let q_enable = meta.query_selector(lt_selector);
                        let check = meta.query_advice(col_c, Rotation::cur());
                        q_enable * (config.lt_configs[i].is_lt(meta, None) - check)
                    })
                    .collect::<Vec<_>>()
            },
        );

        config
    }

    pub fn assign_leaf_hash_and_balances(
        &self,
        mut layouter: impl Layouter<Fp>,
        leaf_hash: Fp,
        leaf_balances: &[Fp],
    ) -> Result<(AssignedCell<Fp, Fp>, Vec<AssignedCell<Fp, Fp>>), Error> {
        let (leaf_hash_cell, leaf_balance_cells) = layouter.assign_region(
            || "assign leaf hash",
            |mut region| {
                let hash = region.assign_advice(
                    || "leaf hash",
                    self.config.advice[MST_WIDTH - 3],
                    0,
                    || Value::known(leaf_hash),
                )?;

                let balances: Vec<AssignedCell<Fp, Fp>> = (0..N_ASSETS)
                    .map(|i| {
                        region.assign_advice(
                            || "leaf balances",
                            self.config.advice[i],
                            0,
                            || Value::known(leaf_balances[i]),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok((hash, balances))
            },
        )?;

        Ok((leaf_hash_cell, leaf_balance_cells))
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<Fp>,
        prev_hash: &AssignedCell<Fp, Fp>,
        prev_balances: &[AssignedCell<Fp, Fp>],
        element_hash: Fp,
        element_balances: [Fp; N_ASSETS],
        index: Fp,
    ) -> Result<(AssignedCell<Fp, Fp>, Vec<AssignedCell<Fp, Fp>>), Error> {
        let (left_hash, left_balances, right_hash, right_balances, computed_sum_cells) = layouter
            .assign_region(
            || "merkle prove layer",
            |mut region| {
                // Row 0
                self.config.bool_selector.enable(&mut region, 0)?;
                self.config.swap_selector.enable(&mut region, 0)?;
                let l1 = prev_hash.copy_advice(
                    || "copy hash cell from previous level",
                    &mut region,
                    self.config.advice[MST_WIDTH - 3],
                    0,
                )?;
                let l2s: Vec<AssignedCell<Fp, Fp>> = prev_balances
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        x.copy_advice(
                            || "copy balance cell from previous level",
                            &mut region,
                            self.config.advice[i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let r1 = region.assign_advice(
                    || "assign element_hash",
                    self.config.advice[MST_WIDTH - 2],
                    0,
                    || Value::known(element_hash),
                )?;
                let r2s: Vec<AssignedCell<Fp, Fp>> = element_balances
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "assign element_balance",
                            self.config.advice[N_ASSETS + i],
                            0,
                            || Value::known(*x),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let index = region.assign_advice(
                    || "assign index",
                    self.config.advice[MST_WIDTH - 1],
                    0,
                    || Value::known(index),
                )?;

                let mut l1_val = l1.value().map(|x| x.to_owned());
                let mut l2_vals: Vec<Value<Fp>> = l2s
                    .iter()
                    .map(|x| x.value().map(|x| x.to_owned()))
                    .collect();
                let mut r1_val = r1.value().map(|x| x.to_owned());
                let mut r2_vals: Vec<Value<Fp>> = r2s
                    .iter()
                    .map(|x| x.value().map(|x| x.to_owned()))
                    .collect();

                // Row 1
                self.config.sum_selector.enable(&mut region, 1)?;

                // if index is 0 return (l1, l2, r1, r2) else return (r1, r2, l1, l2)
                index.value().map(|x| x.to_owned()).map(|x| {
                    (l1_val, l2_vals, r1_val, r2_vals) = if x == Fp::zero() {
                        (
                            l1_val.clone(),
                            l2_vals.clone(),
                            r1_val.clone(),
                            r2_vals.clone(),
                        )
                    } else {
                        (
                            r1_val.clone(),
                            r2_vals.clone(),
                            l1_val.clone(),
                            l2_vals.clone(),
                        )
                    };
                });

                // We need to perform the assignment of the row below according to the index
                let left_hash = region.assign_advice(
                    || "assign left hash to be hashed",
                    self.config.advice[MST_WIDTH - 3],
                    1,
                    || l1_val,
                )?;

                let left_balances: Vec<AssignedCell<Fp, Fp>> = l2_vals
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "assign left balance to be hashed",
                            self.config.advice[i],
                            1,
                            || x.to_owned(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                let right_hash = region.assign_advice(
                    || "assign right hash to be hashed",
                    self.config.advice[MST_WIDTH - 2],
                    1,
                    || r1_val,
                )?;

                let right_balances = r2_vals
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || "assign left balance to be hashed",
                            self.config.advice[N_ASSETS + i],
                            1,
                            || x.to_owned(),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                //Computing the left and right balances sum, element-wise:
                let computed_sums = l2_vals
                    .iter()
                    .zip(r2_vals.iter())
                    .map(|(a, b)| a.value() + b.value());

                // Now we can assign the sum results to the computed_sums cells.
                let computed_sum_cells = computed_sums
                    .enumerate()
                    .map(|(i, x)| {
                        region.assign_advice(
                            || format!("assign sum of left and right balances {}", i),
                            self.config.advice[2 * N_ASSETS + i],
                            1,
                            || x,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok((
                    left_hash,
                    left_balances,
                    right_hash,
                    right_balances,
                    computed_sum_cells,
                ))
            },
        )?;

        // instantiate the poseidon_chip
        let poseidon_chip =
            PoseidonChip::<PoseidonSpecNode, WIDTH_NODE, R_L_NODE, R_L_NODE>::construct(
                self.config.poseidon_config.clone(),
            );

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values

        let hash_input_vec: Vec<AssignedCell<Fp, Fp>> = [left_hash]
            .iter()
            .chain(left_balances.iter())
            .chain([right_hash].iter())
            .chain(right_balances.iter())
            .map(|x| x.to_owned())
            .collect();

        let hash_input: [AssignedCell<Fp, Fp>; R_L_NODE] = match hash_input_vec.try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Failed to convert Vec to Array"),
        };

        let computed_hash = poseidon_chip.hash(
            layouter.namespace(|| format!("hash {} child nodes", 2 * (1 + N_ASSETS))),
            hash_input,
        )?;

        Ok((computed_hash, computed_sum_cells))
    }

    // Enforce computed sum to be less than total assets passed inside the instance column
    pub fn enforce_less_than(
        &self,
        mut layouter: impl Layouter<Fp>,
        prev_computed_sum_cells: &[AssignedCell<Fp, Fp>],
    ) -> Result<(), Error> {
        // Initiate chip config
        let chips: Vec<LtChip<Fp, 8>> = (0..N_ASSETS)
            .map(|i| LtChip::construct(self.config.lt_configs[i]))
            .collect();

        for chip in chips.iter() {
            chip.load(&mut layouter)?;
        }

        layouter.assign_region(
            || "enforce sum to be less than total assets",
            |mut region| {
                // First, copy the computed sums
                let computed_sum_cells = prev_computed_sum_cells
                    .iter()
                    .enumerate()
                    .map(|(i, x)| {
                        x.copy_advice(
                            || "copy computed sum",
                            &mut region,
                            self.config.advice[i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                //Next, copy the total assets from instance columns
                let total_assets_cells: Vec<AssignedCell<Fp, Fp>> = (0..N_ASSETS)
                    .map(|i| {
                        region.assign_advice_from_instance(
                            || "copy total assets",
                            self.config.instance,
                            3 + i,
                            self.config.advice[N_ASSETS + i],
                            0,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                // set check to be equal to 1
                region.assign_advice(
                    || "check",
                    //"Column c" from the spec
                    self.config.advice[self.config.advice.len() - 1],
                    0,
                    || Value::known(Fp::from(1)),
                )?;

                // enable lt seletor
                self.config.lt_selector.enable(&mut region, 0)?;
                //Assign total assets and computed sum cells to the chip:
                for i in 0..N_ASSETS {
                    total_assets_cells[i]
                        .value()
                        .zip(computed_sum_cells[i].value())
                        .map(|(total_assets, computed_sum)| {
                            if let Err(e) = chips[i].assign(
                                &mut region,
                                0,
                                computed_sum.to_owned(),
                                total_assets.to_owned(),
                            ) {
                                println!("Error: {:?}", e);
                            };
                        });
                }

                Ok(())
            },
        )?;

        Ok(())
    }

    // Enforce copy constraint check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
