use super::poseidon::hash::{PoseidonChip, PoseidonConfig};
use super::poseidon::spec::MySpec;
use halo2_proofs::{circuit::*,plonk::*, poly::Rotation};
use gadgets::less_than::{LtChip, LtConfig, LtInstruction};
use eth_types::Field;

const WIDTH: usize = 5;
const RATE: usize = 4;
const L: usize = 4;

#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig <F: Field> {
    pub advice: [Column<Advice>; 5],
    pub bool_selector: Selector,
    pub swap_selector: Selector,
    pub sum_selector: Selector,
    pub lt_selector: Selector,
    pub instance: Column<Instance>,
    pub poseidon_config: PoseidonConfig<F, WIDTH, RATE, L>,
    pub lt_config: LtConfig<F, 8>,
}
#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip <F: Field>{
    config: MerkleSumTreeConfig<F>,
}

impl <F: Field> MerkleSumTreeChip<F> {
    pub fn construct(config: MerkleSumTreeConfig<F>) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        advice: [Column<Advice>; 5],
        instance: Column<Instance>,
    ) -> MerkleSumTreeConfig<F> {
        let col_a = advice[0];
        let col_b = advice[1];
        let col_c = advice[2];
        let col_d = advice[3];
        let col_e = advice[4];

        // create selectors
        let bool_selector = meta.selector();
        let swap_selector = meta.selector();
        let sum_selector = meta.selector();
        let lt_selector = meta.selector();

        // enable equality for leaf_hash copy constraint with instance column (col_a)
        // enable equality for balance_hash copy constraint with instance column (col_b)
        // enable equality for copying left_hash, left_balance, right_hash, right_balance into poseidon_chip (col_a, col_b, col_c, col_d)
        // enable equality for computed_sum copy constraint with instance column (col_e)
        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c); 
        meta.enable_equality(col_d);
        meta.enable_equality(col_e);
        meta.enable_equality(instance);

        // Enforces that e is either a 0 or 1 when the bool selector is enabled
        // s * e * (1 - e) = 0
        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_selector);
            let e = meta.query_advice(col_e, Rotation::cur());
            vec![s * e.clone() * (Expression::Constant(F::from(1)) - e)]
        });

        // Enforces that if the swap bit (e) is on, l1=c, l2=d, r1=a, and r2=b. Otherwise, l1=a, l2=b, r1=c, and r2=d.
        // This applies only when the swap selector is enabled
        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(swap_selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            let d = meta.query_advice(col_d, Rotation::cur());
            let e = meta.query_advice(col_e, Rotation::cur());
            let l1 = meta.query_advice(col_a, Rotation::next());
            let l2 = meta.query_advice(col_b, Rotation::next());
            let r1 = meta.query_advice(col_c, Rotation::next());
            let r2 = meta.query_advice(col_d, Rotation::next());

            vec![
                s.clone() * (e.clone() * Expression::Constant(F::from(2)) * (c.clone() - a.clone())
                    - (l1 - a)
                    - (c - r1)),
                s * (e * Expression::Constant(F::from(2)) * (d.clone() - b.clone())
                    - (l2 - b)
                    - (d - r2)),
            ]
        });

        // Enforces that input_left_balance + input_right_balance = computed_sum
        meta.create_gate("sum constraint", |meta| {
            let s = meta.query_selector(sum_selector);
            let left_balance = meta.query_advice(col_b, Rotation::cur());
            let right_balance = meta.query_advice(col_d, Rotation::cur());
            let computed_sum = meta.query_advice(col_e, Rotation::cur());
            vec![s * (left_balance + right_balance - computed_sum)]
        });

        let hash_inputs = (0..WIDTH).map(|_| meta.advice_column()).collect::<Vec<_>>();

        let poseidon_config = PoseidonChip::<F, MySpec<F, WIDTH, RATE>, WIDTH, RATE, L>::configure(
            meta,
            hash_inputs
        );

        // configure lt chip 
        let lt_config = LtChip::configure(
            meta,
            |meta| meta.query_selector(lt_selector),
            |meta| meta.query_advice(col_a, Rotation::cur()),
            |meta| meta.query_advice(col_b, Rotation::cur()),
        );

        let config = MerkleSumTreeConfig {
            advice: [col_a, col_b, col_c, col_d, col_e],
            bool_selector,
            swap_selector,
            sum_selector,
            lt_selector,
            instance,
            poseidon_config,
            lt_config
        };

        meta.create_gate("verifies that `check` from current config equal to is_lt from LtChip ", |meta| {
            let q_enable = meta.query_selector(lt_selector);

            let check = meta.query_advice(col_c, Rotation::cur());

            vec![q_enable * (config.lt_config.is_lt(meta, None) - check)]
        });

        config

    }

    pub fn assing_leaf_hash_and_balance(
        &self,
        mut layouter: impl Layouter<F>,
        leaf_hash: F,
        leaf_balance: F,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let leaf_hash_cell = layouter.assign_region(
            || "assign leaf hash",
            |mut region| {
                region.assign_advice(|| "leaf hash", self.config.advice[0], 0, || Value::known(leaf_hash))
            },
        )?;

        let leaf_balance_cell = layouter.assign_region(
            || "assign leaf balance",
            |mut region| {
                region.assign_advice(|| "leaf balance", self.config.advice[1], 0, || Value::known(leaf_balance))
            },
        )?;

        Ok((leaf_hash_cell, leaf_balance_cell))
    }

    pub fn merkle_prove_layer(
        &self,
        mut layouter: impl Layouter<F>,
        prev_hash: &AssignedCell<F, F>,
        prev_balance: &AssignedCell<F, F>,
        element_hash: F,
        element_balance: F,
        index: F,
    ) -> Result<(AssignedCell<F, F>, AssignedCell<F, F>), Error> {
        let (left_hash, left_balance, right_hash, right_balance, computed_sum_cell) = layouter
            .assign_region(
                || "merkle prove layer",
                |mut region| {
                    // Row 0 
                    self.config.bool_selector.enable(&mut region, 0)?;
                    self.config.swap_selector.enable(&mut region, 0)?;
                    let l1 = prev_hash.copy_advice(
                        || "copy hash cell from previous level",
                        &mut region,
                        self.config.advice[0],
                        0,
                    )?;
                    let l2 = prev_balance.copy_advice(
                        || "copy balance cell from previous level",
                        &mut region,
                        self.config.advice[1],
                        0,
                    )?;
                    let r1 = region.assign_advice(
                        || "assign element_hash",
                        self.config.advice[2],
                        0,
                        || Value::known(element_hash),
                    )?;
                    let r2 = region.assign_advice(
                        || "assign balance",
                        self.config.advice[3],
                        0,
                        || Value::known(element_balance),
                    )?;
                    let index = region.assign_advice(|| 
                        "assign index", 
                    self.config.advice[4], 
                    0, 
                    || Value::known(index)
                    )?;

                    let mut l1_val = l1.value().map(|x| x.to_owned());
                    let mut l2_val = l2.value().map(|x| x.to_owned());
                    let mut r1_val = r1.value().map(|x| x.to_owned());
                    let mut r2_val = r2.value().map(|x| x.to_owned());
                

                    self.config.sum_selector.enable(&mut region, 1)?;

                    // if index is 0 return (l1, l2, r1, r2) else return (r1, r2, l1, l2)
                    index.value().map(|x| x.to_owned()).map(|x| {
                        (l1_val, l2_val, r1_val, r2_val) = if x == F::zero() {
                            (l1_val, l2_val, r1_val, r2_val)
                        } else {
                            (r1_val, r2_val, l1_val, l2_val)
                        };
                    });

                    // We need to perform the assignment of the row below according to the index
                    let left_hash = region.assign_advice(
                        || "assign left hash to be hashed",
                        self.config.advice[0],
                        1,
                        || l1_val,
                    )?;

                    let left_balance = region.assign_advice(
                        || "assign left balance to be hashed",
                        self.config.advice[1],
                        1,
                        || l2_val,
                    )?;

                    let right_hash = region.assign_advice(
                        || "assign right hash to be hashed",
                        self.config.advice[2],
                        1,
                        || r1_val,
                    )?;

                    let right_balance = region.assign_advice(
                        || "assign right balance to be hashed",
                        self.config.advice[3],
                        1,
                        || r2_val,
                    )?;

                    let computed_sum = left_balance.value().zip(right_balance.value()).map(|(a, b)| *a + b);

                    // Now we can assign the sum result to the computed_sum cell.
                    let computed_sum_cell = region.assign_advice(
                        || "assign sum of left and right balance",
                        self.config.advice[4],
                        1,
                        || computed_sum,
                    )?;

                    Ok((
                        left_hash,
                        left_balance,
                        right_hash,
                        right_balance,
                        computed_sum_cell,
                    ))
                },
            )?;

        // instantiate the poseidon_chip
        let poseidon_chip = PoseidonChip::<F, MySpec<F, WIDTH, RATE>, WIDTH, RATE, L>::construct(
            self.config.poseidon_config.clone(),
        );

        // The hash function inside the poseidon_chip performs the following action
        // 1. Copy the left and right cells from the previous row
        // 2. Perform the hash function and assign the digest to the current row
        // 3. Constrain the digest to be equal to the hash of the left and right values
        let computed_hash = poseidon_chip.hash(
            layouter.namespace(|| "hash four child nodes"),
            [left_hash, left_balance, right_hash, right_balance],
        )?;

        Ok((computed_hash, computed_sum_cell))
    }

    // Enforce computed sum to be less than total assets passed inside the instance column
    pub fn enforce_less_than(
        &self,
        mut layouter: impl Layouter<F>,
        prev_computed_sum_cell: &AssignedCell<F, F>,
        computed_sum: F,
        total_assets: F,
    ) -> Result<(), Error> {

        // Initiate chip config
        let chip = LtChip::construct(self.config.lt_config);

        layouter.assign_region(
            || "enforce sum to be less than total assets",
            |mut region| {

                // copy the computed sum to the cell in the first column
                prev_computed_sum_cell.copy_advice(
                    || "copy computed sum",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;

                // copy the total assets from instance column to the cell in the second column
                region.assign_advice_from_instance(
                    || "copy total assets",
                    self.config.instance,
                    3,
                    self.config.advice[1], 
                    0
                )?;

                // set check to be equal to 1
                region.assign_advice(
                    || "check",
                    self.config.advice[2],
                    0,
                    || Value::known(F::from(1)),
                )?;

                // enable lt seletor 
                self.config.lt_selector.enable(&mut region, 0)?;

                chip.assign(&mut region, 0, computed_sum, total_assets)?;

                Ok(())
            },
        )?;

        Ok(())
    }

    // Enforce permutation check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}
