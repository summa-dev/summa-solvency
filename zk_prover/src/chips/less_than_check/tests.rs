use crate::chips::less_than_check::lt_check::{CheckLtChip, CheckLtConfig};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error},
};

#[derive(Debug, Clone)]
pub struct TestConfig<const N_BYTES: usize> {
    pub check_lt_config: CheckLtConfig<N_BYTES>,
    pub advice_cols: [Column<Advice>; 3],
}

impl<const N_BYTES: usize> TestConfig<N_BYTES> {
    /// Generic method to assign witness value to a cell in the witness table to advice column `column_index`. `object_to_assign` is label to identify the object being assigned. It is useful for debugging.
    pub fn assign_value(
        &self,
        mut layouter: impl Layouter<Fp>,
        value: Fp,
        column_index: usize,
        object_to_assign: &'static str,
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        layouter.assign_region(
            || format!("assign {}", object_to_assign),
            |mut region| {
                region.assign_advice(
                    || "value",
                    self.advice_cols[column_index],
                    0,
                    || Value::known(value),
                )
            },
        )
    }
}

// The test circuit takes two inputs lhs and rhs.
// Leverages CheckLtChip to enforce that lhs < rhs.
#[derive(Default, Clone, Debug)]
struct TestCircuit<const N_BYTES: usize> {
    pub lhs: Fp,
    pub rhs: Fp,
}

impl<const N_BYTES: usize> Circuit<Fp> for TestCircuit<N_BYTES> {
    type Config = TestConfig<N_BYTES>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let advice_cols = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        meta.enable_equality(advice_cols[0]);
        meta.enable_equality(advice_cols[1]);
        meta.enable_equality(advice_cols[2]);

        let range = meta.fixed_column();
        meta.enable_constant(range);

        let check_lt_enable = meta.selector();
        let toggle_lookup_check = meta.complex_selector();

        let check_lt_config = CheckLtChip::<N_BYTES>::configure(
            meta,
            advice_cols[0],
            advice_cols[1],
            advice_cols[2],
            range,
            check_lt_enable,
            toggle_lookup_check,
        );

        {
            TestConfig {
                advice_cols,
                check_lt_config,
            }
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Initiate the check lt chip
        let check_lt_chip = CheckLtChip::construct(config.check_lt_config);

        // Assign lhs, rhs witnesses to advice columns
        let lhs_cell =
            config.assign_value(layouter.namespace(|| "assign lhs"), self.lhs, 0, "lhs")?;

        let rhs_cell =
            config.assign_value(layouter.namespace(|| "assign rhs"), self.rhs, 1, "rhs")?;

        // Assign lhs and rhs
        check_lt_chip.assign(
            layouter.namespace(|| "assign lhs and rhs"),
            &lhs_cell,
            &rhs_cell,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod testing {
    use super::TestCircuit;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };

    // lhs = 1
    // rhs = 200
    // N_BYTES = 2
    #[test]
    fn valid_check_lt() {
        let k = 9;

        // a: new value
        let lhs = Fp::from(1);
        let rhs = Fp::from(200);

        let circuit = TestCircuit::<2> { lhs, rhs };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    // lhs = 1
    // rhs = 200
    // N_BYTES = 10
    #[test]
    fn valid_check_lt_2() {
        let k = 9;

        // a: new value
        let lhs = Fp::from(1);
        let rhs = Fp::from(200);

        let circuit = TestCircuit::<10> { lhs, rhs };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    // lhs = 200
    // rhs = 1
    // lhs - rhs + range = 200 - 1 + 2^16 = 199 + 2^16 which is out of range.
    #[test]
    fn invalid_check_lt() {
        let k = 9;

        // a: new value
        let lhs = Fp::from(200);
        let rhs = Fp::from(1);

        let circuit = TestCircuit::<2> { lhs, rhs };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 2).into(),
                    location: FailureLocation::InRegion {
                        region: (4, "assign value to perform range check").into(),
                        offset: 2
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Fixed, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 256 }
                },
            ])
        );
    }

    // lhs = 200
    // rhs = 200
    // lhs - rhs + range = 200 - 200 + 2^16 = 2^16 which is out of range.
    #[test]
    fn invalid_check_lt_2() {
        let k = 9;

        // a: new value
        let lhs = Fp::from(200);
        let rhs = Fp::from(200);

        let circuit = TestCircuit::<2> { lhs, rhs };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                VerifyFailure::Permutation {
                    column: (Any::advice(), 2).into(),
                    location: FailureLocation::InRegion {
                        region: (4, "assign value to perform range check").into(),
                        offset: 2
                    }
                },
                VerifyFailure::Permutation {
                    column: (Any::Fixed, 0).into(),
                    location: FailureLocation::OutsideRegion { row: 256 }
                },
            ])
        );
    }

    #[cfg(feature = "dev-graph")]
    #[test]
    fn print_check_lt() {
        use plotters::prelude::*;

        let root =
            BitMapBackend::new("prints/lt-check-layout.png", (1024, 3096)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Lt Check Layout", ("sans-serif", 60)).unwrap();

        let circuit = TestCircuit::<2> {
            lhs: Fp::from(1),
            rhs: Fp::from(200),
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(9, &circuit, &root)
            .unwrap();
    }
}
