use halo2_proofs::circuit::{AssignedCell, Layouter};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector};
use halo2_proofs::poly::Rotation;

/// Configuration for the Merkle Sum Tree Chip
///
/// # Fields
///
/// * `advice`: advice columns to fit the witness values.
/// * `bool_and_swap_selector`: Selector to enable the bool and swap constraints.
/// * `sum_selector`: Selector to enable the sum constraints.
#[derive(Debug, Clone)]
pub struct MerkleSumTreeConfig {
    advice: [Column<Advice>; 3],
    bool_and_swap_selector: Selector,
    sum_selector: Selector,
}

/// Chip that performs various constraints related to a Merkle Sum Tree data structure such as:
///
/// * `s * swap_bit * (1 - swap_bit) = 0` (if `bool_and_swap_selector` is toggled). It basically enforces that swap_bit is either a 0 or 1.
/// * `s * (element_r_cur - element_l_cur) * swap_bit + element_l_cur - element_l_next = 0` (if `bool_and_swap_selector` is toggled).
/// * `s * (element_l_cur - element_r_cur) * swap_bit + element_r_cur - element_r_next = 0` (if `bool_and_swap_selector` is toggled).
/// These 2 constraints enforce that if the swap_bit is equal to 1, the values will be swapped on the next row. If the swap_bit is equal to 0, the values will not be swapped on the next row.
/// * `s * (left_balance + right_balance - computed_sum)`. It constraints the computed sum to be equal to the sum of the left and right balances (if `sum_selector` is toggled).

#[derive(Debug, Clone)]
pub struct MerkleSumTreeChip<const N_CURRENCIES: usize> {
    config: MerkleSumTreeConfig,
}

impl<const N_CURRENCIES: usize> MerkleSumTreeChip<N_CURRENCIES> {
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
            let element_l_cur = meta.query_advice(col_a, Rotation::cur());
            let element_r_cur = meta.query_advice(col_b, Rotation::cur());
            let element_l_next = meta.query_advice(col_a, Rotation::next());
            let element_r_next = meta.query_advice(col_b, Rotation::next());

            // element_l_next = (element_r_cur - element_l_cur)*s + element_l_cur
            let swap_constraint_1 = s.clone()
                * ((element_r_cur.clone() - element_l_cur.clone()) * swap_bit.clone()
                    + element_l_cur.clone()
                    - element_l_next);

            // element_r_next = (element_l_cur - element_r_cur)*s + element_r_cur
            let swap_constraint_2 = s
                * ((element_l_cur - element_r_cur.clone()) * swap_bit + element_r_cur
                    - element_r_next);

            vec![swap_constraint_1, swap_constraint_2]
        });

        meta.create_gate("sum constraint", |meta| {
            (0..N_CURRENCIES)
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

    /// Swap the values of two cells in a region following this layout on 3 advice columns:
    ///
    /// | a              | b                 | c          |
    /// | ------------   | -------------     | ---------- |
    /// | `current_hash` | `sibling_hash`    | `1`        |
    /// | `sibling_hash` | `current_hash`    | -          |
    ///
    /// At row 0 bool_and_swap_selector is enabled
    /// If swap_bit is 0, the values will remain the same on the next row
    /// If swap_bit is 1, the values will be swapped on the next row
    pub fn swap_hashes_per_level(
        &self,
        mut layouter: impl Layouter<Fp>,
        current_hash: &AssignedCell<Fp, Fp>,
        sibling_hash: &AssignedCell<Fp, Fp>,
        swap_bit_assigned: &AssignedCell<Fp, Fp>,
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
                let r1 = sibling_hash.copy_advice(
                    || "copy element hash from assigned value",
                    &mut region,
                    self.config.advice[1],
                    0,
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

    /// Assign the nodes balance for a single currency in a region following this layout on 3 advice columns:
    ///
    /// | a                 | b                 | c          |
    /// | ------------      | -------------     | ---------- |
    /// | `current_balance` | `element_balance` | `sum`      |
    ///
    /// At row 0 sum_selector is enabled.
    pub fn sum_balances_per_level(
        &self,
        mut layouter: impl Layouter<Fp>,
        current_balance: &AssignedCell<Fp, Fp>,
        element_balance: &AssignedCell<Fp, Fp>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || "sum nodes balances per currency",
            |mut region| {
                // enable the sum_selector at row 0
                self.config.sum_selector.enable(&mut region, 0)?;

                // copy the current_balances to the column self.config.advice[0] at offset 0
                let current_balance = current_balance.copy_advice(
                    || "copy current balance from prev level",
                    &mut region,
                    self.config.advice[0],
                    0,
                )?;

                // assign the element_balance to the column self.config.advice[1] at offset 0
                let element_balance = element_balance.copy_advice(
                    || "element balance",
                    &mut region,
                    self.config.advice[1],
                    0,
                )?;

                // Extract the values from the cell
                let current_balance_val = current_balance.value().copied();
                let element_balance_val = element_balance.value().copied();

                // compute the sum of the two balances and assign it to the column self.config.advice[2] at offset 0
                let sum = current_balance_val
                    .zip(element_balance_val)
                    .map(|(a, b)| a + b);
                let sum_cell =
                    region.assign_advice(|| "sum of balances", self.config.advice[2], 0, || sum)?;

                Ok(sum_cell)
            },
        )
    }
}
