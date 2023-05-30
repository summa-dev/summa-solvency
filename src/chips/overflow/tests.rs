use halo2_proofs::{circuit::*, plonk::*};

use halo2_proofs::halo2curves::bn256::Fr as Fp;
use crate::chips::overflow::overflow_check::{OverflowCheckConfig, OverflowChip};

#[derive(Default)]
struct OverflowCheckCircuit<const MAX_BITS: u8, const ACC_COLS: usize> {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl<const MAX_BITS: u8, const ACC_COLS: usize> Circuit<Fp> for OverflowCheckCircuit<MAX_BITS, ACC_COLS> {
    type Config = OverflowCheckConfig<MAX_BITS, ACC_COLS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        OverflowChip::configure(
            meta,
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let chip = OverflowChip::construct(config);

        chip.load(&mut layouter)?;

        // check overflow
        chip.assign(layouter.namespace(|| "checking overflow value a"), self.a)?;
        chip.assign(layouter.namespace(|| "checking overflow value b"), self.b)?;
        chip.assign(
            layouter.namespace(|| "checking overflow value a + b"),
            self.a + self.b,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::OverflowCheckCircuit;
    use halo2_proofs::{
        circuit::Value,
        plonk::Any, 
        dev::{FailureLocation, MockProver, VerifyFailure}, halo2curves::{bn256::Fr as Fp}};

    #[test]
    fn test_none_overflow_16bits_case() {
        let k = 5;

        // a: new value
        let a = Value::known(Fp::from((1 << 16) - 2));
        let b = Value::known(Fp::from(1));

        let circuit = OverflowCheckCircuit::<4, 4> { a, b };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_overflow_16bits_case() {
        let k = 5;

        let a = Value::known(Fp::from((1 << 16) - 2));
        let b = Value::known(Fp::from(3));

        let circuit = OverflowCheckCircuit::<4, 4> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert_eq!(
            invalid_prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: ((0, "equality check between decomposed_value and value").into(), 0, "").into(),
                location: FailureLocation::InRegion {
                    region: (3, "assign decomposed values").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 0).into(), 0).into(), "0x10001".to_string()),
                    (((Any::advice(), 1).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 2).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 3).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 0).into(), "1".to_string()),
                ]
            }])
        );
    }

    #[test]
    fn test_overflow_252bits_case() {
        let k = 13;

        let a = Value::known(Fp::from(0) - Fp::one());
        let b = Value::known(Fp::from(2));

        let circuit = OverflowCheckCircuit::<12, 21> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: ((0, "equality check between decomposed_value and value").into(), 0, "").into(),
                location: FailureLocation::InRegion {
                    region: (1, "assign decomposed values").into(),
                    offset: 0
                },
                cell_values: vec![
                    (((Any::advice(), 0).into(), 0).into(), "-1".to_string()),
                    (((Any::advice(), 1).into(), 0).into(), "0x64".to_string()),
                    (((Any::advice(), 2).into(), 0).into(), "0x4e7".to_string()),
                    (((Any::advice(), 3).into(), 0).into(), "0x2e1".to_string()),
                    (((Any::advice(), 4).into(), 0).into(), "0x31a".to_string()),
                    (((Any::advice(), 5).into(), 0).into(), "0x29".to_string()),
                    (((Any::advice(), 6).into(), 0).into(), "0xb85".to_string()),
                    (((Any::advice(), 7).into(), 0).into(), "0x45".to_string()),
                    (((Any::advice(), 8).into(), 0).into(), "0xb68".to_string()),
                    (((Any::advice(), 9).into(), 0).into(), "0x181".to_string()),
                    (((Any::advice(), 10).into(), 0).into(), "0x585".to_string()),
                    (((Any::advice(), 11).into(), 0).into(), "0xd28".to_string()),
                    (((Any::advice(), 12).into(), 0).into(), "0x33e".to_string()),
                    (((Any::advice(), 13).into(), 0).into(), "0x848".to_string()),
                    (((Any::advice(), 14).into(), 0).into(), "0x79b".to_string()),
                    (((Any::advice(), 15).into(), 0).into(), "0x970".to_string()),
                    (((Any::advice(), 16).into(), 0).into(), "0x914".to_string()),
                    (((Any::advice(), 17).into(), 0).into(), "0x3e1".to_string()),
                    (((Any::advice(), 18).into(), 0).into(), "0xf59".to_string()),
                    (((Any::advice(), 19).into(), 0).into(), "0x3f0".to_string()),
                    (((Any::advice(), 20).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 21).into(), 0).into(), "0".to_string()),
                ]
            }])
        );
    }
}
