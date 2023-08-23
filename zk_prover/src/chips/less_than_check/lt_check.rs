use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};

use crate::chips::range::{
    range_check::{RangeCheckChip, RangeCheckConfig},
    utils::pow_of_two,
};

/// Config for the CheckLt chip.
#[derive(Clone, Copy, Debug)]
pub struct CheckLtConfig<const N_BYTES: usize> {
    /// Denotes the lhs value.
    lhs_col: Column<Advice>,
    /// Denotes the rhs value.
    rhs_col: Column<Advice>,
    /// Denotes the diff value.
    diff_col: Column<Advice>,
    /// Denotes the selector used to enforce the LT constraint between lhs and rhs.
    check_lt_selector: Selector,
    /// Configuration for the RangeCheck chip.
    range_check_config: RangeCheckConfig<N_BYTES>,
}

/// Constrains that 'lhs' is less than 'rhs'.
///
/// Assumes that `lhs` and `rhs` are known to have <= N_BYTES bytes.
///
/// Note: This may fail silently if `lhs` or `rhs` have more than N_BYTES
///
/// Patterned after [Axiom `check_less_than`](https://axiom-crypto.github.io/halo2-lib/src/halo2_base/gates/range.rs.html#213-219)
///
/// It performs the following constraint:
/// * `diff = lhs - rhs + 2**(N_BYTES*8)`. When check_lt_selector is 1, this constraint is enforced.
/// * `diff ∈ N_BYTES range for diff cell

#[derive(Clone, Copy, Debug)]
pub struct CheckLtChip<const N_BYTES: usize> {
    config: CheckLtConfig<N_BYTES>,
}

impl<const N_BYTES: usize> CheckLtChip<N_BYTES> {
    /// Configures the CheckLtChip.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        lhs_col: Column<Advice>,
        rhs_col: Column<Advice>,
        diff_col: Column<Advice>,
        range: Column<Fixed>,
        check_lt_selector: Selector,
        toggle_lookup_check: Selector,
    ) -> CheckLtConfig<N_BYTES> {
        meta.create_gate("lt gate", |meta| {
            let lhs_expr = meta.query_advice(lhs_col, Rotation::cur());
            let rhs_expr = meta.query_advice(rhs_col, Rotation::cur());
            let diff_expr = meta.query_advice(diff_col, Rotation::cur());
            let check_lt_selector: Expression<Fp> = meta.query_selector(check_lt_selector);

            let range_fp = pow_of_two(N_BYTES * 8);

            let range_expr = Expression::Constant(range_fp);

            vec![check_lt_selector * (lhs_expr - rhs_expr + range_expr - diff_expr)]
        });

        let range_check_config =
            RangeCheckChip::configure(meta, diff_col, range, toggle_lookup_check);

        CheckLtConfig {
            lhs_col,
            rhs_col,
            diff_col,
            check_lt_selector,
            range_check_config,
        }
    }

    /// Constructs a CheckLtChip given a config.
    pub fn construct(config: CheckLtConfig<N_BYTES>) -> CheckLtChip<N_BYTES> {
        CheckLtChip { config }
    }

    /// Assign `lhs`, `rhs` and `diff` to the region.
    pub fn assign(
        &self,
        mut layouter: impl Layouter<Fp>,
        lhs_cell: &AssignedCell<Fp, Fp>,
        rhs_cell: &AssignedCell<Fp, Fp>,
    ) -> Result<(), Error> {
        let diff_cell = layouter.assign_region(
            || "assign lhs, rhs and diff to the region",
            |mut region| {
                // enable check_lt_selector at offset 0
                self.config.check_lt_selector.enable(&mut region, 0)?;

                // copy `lhs_cell` to `lhs_col` column at offset 0
                lhs_cell.copy_advice(|| "copy lhs", &mut region, self.config.lhs_col, 0)?;

                // copy `rhs_cell` to `rhs_col` column at offset 0
                rhs_cell.copy_advice(|| "copy rhs", &mut region, self.config.rhs_col, 0)?;

                // Compute diff_val starting from lhs_cell and rhs_cell
                let diff_val = lhs_cell.value().zip(rhs_cell.value()).map(|(lhs, rhs)| {
                    let mut diff = lhs - rhs;
                    let range = pow_of_two(N_BYTES * 8);
                    diff += range;
                    diff
                });

                let diff_cell = region.assign_advice(
                    || "assign diff to the region",
                    self.config.diff_col,
                    0,
                    || diff_val,
                )?;

                Ok(diff_cell)
            },
        )?;

        // Instantiate the range check chip.
        let range_check_chip = RangeCheckChip::construct(self.config.range_check_config);

        // load the lookup table for range check
        range_check_chip.load(&mut layouter)?;

        // assign diff_cell to the range check chip to perform range check
        range_check_chip.assign(layouter, &diff_cell)?;

        Ok(())
    }
}
