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
    use halo2_proofs::{circuit::Value, dev::MockProver, halo2curves::bn256::Fr as Fp};
    #[test]
    fn test_none_overflow_case() {
        let k = 5;

        // a: new value
        let a = Value::known(Fp::from((1 << 16) - 2));
        let b = Value::known(Fp::from(1));

        let circuit = OverflowCheckCircuit::<4, 4> { a, b };
        let prover = MockProver::run(k, &circuit, vec![]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn test_overflow_case() {
        let k = 5;

        // a: new value
        let a = Value::known(Fp::from((1 << 16) - 2));
        let b = Value::known(Fp::from(3));

        let circuit = OverflowCheckCircuit::<4, 4> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();
        assert!(invalid_prover.verify().is_err());
    }
}
