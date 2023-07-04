use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

/// Configuration for the Merkle Sum Tree Chip
///
/// # Fields
///
/// * `advice`: advice columns to fit the witness values.
/// * `bool_and_swap_selector`: Selector to toggle the bool and swap constraints.
/// * `sum_selector`: Selector to toggle the sum constraints.
#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig {
    pub advice: [Column<Advice>; 3],
    pub bool_and_swap_selector: Selector,
    pub sum_selector: Selector,
}

/// Chip that performs various constraints related to a Merkle Sum Tree data structure such as:
///
/// * `s * swap_bit * (1 - swap_bit) = 0` (if `bool_and_swap_selector` is toggled). It basically enforces that swap_bit is either a 0 or 1.
/// * `s * swap_bit * ((elelment_l_next - elelment_l_cur) - (elelment_r_cur - elelment_r_next))`. Enforces that if the swap_bit is equal to 1, the values will be swapped on the next row (if `bool_and_swap_selector` is toggled).
/// * `s * (left_balance + right_balance - computed_sum)`. It constraints the computed sum to be equal to the sum of the left and right balances (if `sum_selector` is toggled).
#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip<const N_ASSETS: usize> {
    config: MerkleSumTreeConfig,
}

impl<const N_ASSETS: usize> MerkleSumTreeChip<N_ASSETS> {
    pub fn construct(config: MerkleSumTreeConfig) -> Self {
        Self { config }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        advice: [Column<Advice>; 3],
        selectors: [Selector; 2],
    ) -> MerkleSumTreeConfig {
        let col_a: Column<Advice> = advice[0];
        let col_b: Column<Advice> = advice[1];
        let col_c: Column<Advice> = advice[2];

        let bool_and_swap_selector = selectors[0];
        let sum_selector = selectors[1];

        meta.create_gate("bool constraint", |meta| {
            let s = meta.query_selector(bool_and_swap_selector);
            let swap_bit = meta.query_advice(col_c, Rotation::cur());
            vec![s * swap_bit.clone() * (Expression::Constant(Fp::from(1)) - swap_bit)]
        });

        meta.create_gate("swap constraint", |meta| {
            let s = meta.query_selector(bool_and_swap_selector);
            let swap_bit = meta.query_advice(col_c, Rotation::cur());
            let elelment_l_cur = meta.query_advice(col_a, Rotation::cur());
            let elelment_r_cur = meta.query_advice(col_b, Rotation::cur());
            let elelment_l_next = meta.query_advice(col_a, Rotation::next());
            let elelment_r_next = meta.query_advice(col_b, Rotation::next());

            let swap_constraint = s
                * swap_bit
                * ((elelment_l_next - elelment_l_cur) - (elelment_r_cur - elelment_r_next));

            vec![swap_constraint]
        });

        meta.create_gate("sum constraint", |meta| {
            (0..N_ASSETS)
                .map(|_| {
                    let left_balance = meta.query_advice(col_a, Rotation::cur());
                    let right_balance = meta.query_advice(col_b, Rotation::cur());
                    let computed_sum = meta.query_advice(col_c, Rotation::cur());
                    let s = meta.query_selector(sum_selector);
                    s * (left_balance + right_balance - computed_sum)
                })
                .collect::<Vec<_>>()
        });

        MerkleSumTreeConfig {
            advice,
            bool_and_swap_selector,
            sum_selector,
        }
    }

    /// Assigns the entry hash and balances to the tree following this layout on a single column and returns the assigned cells:
    ///
    /// | a |
    /// | -- |
    /// | entry hash |
    /// | entry_balance_0 |
    /// | entry_balance_1 |
    /// | ... |
    /// | entry_balance_N |
    pub fn assign_entry_hash_and_balances(
        &self,
        mut layouter: impl Layouter<Fp>,
        entry_hash: Fp,
        entry_balances: &[Fp],
    ) -> Result<(AssignedCell<Fp, Fp>, Vec<AssignedCell<Fp, Fp>>), Error> {
        let (entry_hash_cell, entry_balance_cells) = layouter.assign_region(
            || "assign entry hash",
            |mut region| {
                let hash = region.assign_advice(
                    || "entry hash",
                    self.config.advice[0],
                    0,
                    || Value::known(entry_hash),
                )?;

                let balances: Vec<AssignedCell<Fp, Fp>> = (0..N_ASSETS)
                    .map(|i| {
                        region.assign_advice(
                            || "entry balances",
                            self.config.advice[0],
                            i + 1,
                            || Value::known(entry_balances[i]),
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                Ok((hash, balances))
            },
        )?;

        Ok((entry_hash_cell, entry_balance_cells))
    }

    // Assigns the swap bit to a cell and returns it
    pub fn assing_swap_bit(
        &self,
        mut layouter: impl Layouter<Fp>,
        swap_bit: Fp,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let swap_bit_cell = layouter.assign_region(
            || "assign swap bit",
            |mut region| {
                let swap_bit_cell = region.assign_advice(
                    || "swap bit",
                    self.config.advice[0],
                    0,
                    || Value::known(swap_bit),
                )?;

                Ok(swap_bit_cell)
            },
        )?;
        Ok(swap_bit_cell)
    }

    /// Assign the hashes for node in a region following this layout on 3 advice columns:
    ///
    /// | a              | b                 | c          |
    /// | ------------   | -------------     | ---------- |
    /// | `current_hash` | `element_hash`    | `swap_bit` |
    /// | `current_hash` | `element_hash`    | -          |
    ///
    /// At row 0 bool_and_swap_selector is enabled
    pub fn assign_nodes_hashes_per_level(
        &self,
        mut layouter: impl Layouter<Fp>,
        current_hash: &AssignedCell<Fp, Fp>,
        element_hash: Fp,
        swap_bit_assigned: AssignedCell<Fp, Fp>,
    ) -> Result<(AssignedCell<Fp, Fp>, AssignedCell<Fp, Fp>), Error> {
        layouter.assign_region(
            || "assign nodes hashes per merkle tree level",
            |mut region| {
                // enable the bool_and_swap_selector at row 0
                self.config.bool_and_swap_selector.enable(&mut region, 0)?;

                // copy the current_hash to the column self.config.advice[0] at offset 0
                let l1 = current_hash.copy_advice(
                    || "copy current hash from previous level",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;

                // assign the element hash to the column self.config.advice[1] at offset 0
                let r1 = region.assign_advice(
                    || "element hash",
                    self.config.advice[1],
                    0,
                    || Value::known(element_hash),
                )?;

                // assign the swap_bit to the column self.config.advice[2] at offset 0
                let swap_bit = swap_bit_assigned.copy_advice(
                    || "swap bit",
                    &mut region,
                    self.config.advice[2],
                    0,
                )?;

                // Extract the value from the cell
                let mut l1_val = l1.value().copied();
                let mut r1_val = r1.value().copied();

                // perform the swap according to the swap bit
                // if swap_bit is 0 return (l1, r1) else return (r1, l1)
                swap_bit.value().copied().map(|x| {
                    (l1_val, r1_val) = if x == Fp::zero() {
                        (l1_val, r1_val)
                    } else {
                        (r1_val, l1_val)
                    };
                });

                // Perform the assignment according to the swap at offset 1
                let left_hash = region.assign_advice(
                    || "assign left hash after swap",
                    self.config.advice[0],
                    1,
                    || l1_val,
                )?;

                let right_hash = region.assign_advice(
                    || "assign right hash after swap",
                    self.config.advice[1],
                    1,
                    || r1_val,
                )?;

                Ok((left_hash, right_hash))
            },
        )
    }

    /// Assign the nodes balance for a single asset in a region following this layout on 3 advice columns:
    ///
    /// | a                 | b                 | c          |
    /// | ------------      | -------------     | ---------- |
    /// | `current_balance` | `element_balance` | `swap_bit` |
    /// | `current_balance` | `element_balance` | `sum`      |
    ///
    /// At row 0 bool_and_swap_selector is enabled.
    /// At row 1 sum_selector is enabled
    pub fn assign_nodes_balance_per_asset(
        &self,
        mut layouter: impl Layouter<Fp>,
        current_balance: &AssignedCell<Fp, Fp>,
        element_balance: Fp,
        swap_bit_assigned: AssignedCell<Fp, Fp>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        layouter.assign_region(
            || "assign nodes balances per asset",
            |mut region| {
                // enable the bool_and_swap_selector at row 0
                self.config.bool_and_swap_selector.enable(&mut region, 0)?;

                // copy the current_balances to the column self.config.advice[0] at offset 0
                let l1 = current_balance.copy_advice(
                    || "copy current balance from prev level",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;

                // assign the element_balance to the column self.config.advice[1] at offset 0
                let r1 = region.assign_advice(
                    || "element balance",
                    self.config.advice[1],
                    0,
                    || Value::known(element_balance),
                )?;

                // assign the swap_bit to the column self.config.advice[2] at offset 0
                let swap_bit = swap_bit_assigned.copy_advice(
                    || "swap bit",
                    &mut region,
                    self.config.advice[2],
                    0,
                )?;

                // Extract the value from the cell
                let mut l1_val = l1.value().copied();
                let mut r1_val = r1.value().copied();

                // perform the swap according to the swap bit
                // if swap_bit is 0 return (l1, r1) else return (r1, l1)
                swap_bit.value().copied().map(|x| {
                    (l1_val, r1_val) = if x == Fp::zero() {
                        (l1_val, r1_val)
                    } else {
                        (r1_val, l1_val)
                    };
                });

                // Perform the assignment according to the swap at offset 1
                let left_balance_asset = region.assign_advice(
                    || "assign left balance after swap",
                    self.config.advice[0],
                    1,
                    || l1_val,
                )?;

                let right_balance_asset = region.assign_advice(
                    || "assign right balance after swap",
                    self.config.advice[1],
                    1,
                    || r1_val,
                )?;

                // enable the sum_selector at offset 1
                self.config.sum_selector.enable(&mut region, 1)?;

                // compute the sum of the two balances and assign it to the column self.config.advice[2] at offset 1
                let sum = l1_val.zip(r1_val).map(|(a, b)| a + b);
                let sum_cell =
                    region.assign_advice(|| "sum of balances", self.config.advice[2], 1, || sum)?;

                Ok((left_balance_asset, right_balance_asset, sum_cell))
            },
        )
    }
}
