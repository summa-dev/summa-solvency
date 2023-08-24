use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use halo2_proofs::plonk::{Advice, Column, Error};
use halo2_proofs::{circuit::AssignedCell, plonk::Instance};

/// Trait containing common methods for all circuits
pub trait CircuitBase {
    /// Enforce copy constraint check between input cell and instance column at row passed as input
    fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        row: usize,
        instance: Column<Instance>,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), instance, row)
    }

    /// Generic method to assign `value` to a cell in the witness table to advice column `advice_col`. `object_to_assign` is label to identify the object being assigned. It is useful for debugging.
    /// Returns the assigned cell.
    fn assign_value_to_witness(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Fp,
        object_to_assign: &'static str,
        advice_col: Column<Advice>,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || format!("assign {}", object_to_assign),
            |mut region| region.assign_advice(|| "value", advice_col, 0, || Value::known(value)),
        )
    }
}
