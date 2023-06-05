use halo2_proofs::{circuit::*, plonk::*};

use crate::chips::overflow::overflow_check::{OverflowCheckConfig, OverflowChip};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

#[derive(Default)]
struct OverflowCheckCircuit<const MAX_BITS: u8, const ACC_COLS: usize> {
    pub a: Value<Fp>,
    pub b: Value<Fp>,
}

impl<const MAX_BITS: u8, const ACC_COLS: usize> Circuit<Fp>
    for OverflowCheckCircuit<MAX_BITS, ACC_COLS>
{
    type Config = OverflowCheckConfig<MAX_BITS, ACC_COLS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        OverflowChip::configure(meta)
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
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };

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
                constraint: (
                    (0, "equality check between decomposed_value and value").into(),
                    0,
                    ""
                )
                    .into(),
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
    fn test_overflow_251bits_case_1() {
        let k = 13;

        // In case, the left_balance(i.e user balance) is maximum value
        let a = Value::known(Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]));
        let b = Value::known(Fp::from(1));

        let circuit = OverflowCheckCircuit::<12, 21> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (0, "equality check between decomposed_value and value").into(),
                    0,
                    ""
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (3, "assign decomposed values").into(),
                    offset: 0
                },
                cell_values: vec![
                    (
                        ((Any::advice(), 0).into(), 0).into(),
                        "0x1000000000000000000000000000000000000000000000000000000000000000"
                            .to_string()
                    ),
                    (((Any::advice(), 1).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 2).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 3).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 5).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 6).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 7).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 8).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 9).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 10).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 11).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 12).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 13).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 14).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 15).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 16).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 17).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 18).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 19).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 20).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 21).into(), 0).into(), "0".to_string()),
                ]
            }])
        );
    }

    // this test case with different overflow advice columns
    #[test]
    fn test_overflow_251bits_case_2() {
        let k = 11;

        //  left and right balance are equal to max value
        let max_balance = Value::known(Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]));

        let circuit = OverflowCheckCircuit::<8, 31> {
            a: max_balance,
            b: max_balance,
        };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        fn gen_errors(region_num: usize, first_advice: &str, last_advice: &str) -> VerifyFailure {
            VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (0, "equality check between decomposed_value and value").into(),
                    0,
                    "",
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (region_num, "assign decomposed values").into(),
                    offset: 0,
                },
                cell_values: vec![
                    (
                        ((Any::advice(), 0).into(), 0).into(),
                        first_advice.to_string(),
                    ),
                    (((Any::advice(), 1).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 2).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 3).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 5).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 6).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 7).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 8).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 9).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 10).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 11).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 12).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 13).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 14).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 15).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 16).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 17).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 18).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 19).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 20).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 21).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 22).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 23).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 24).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 25).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 26).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 27).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 28).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 29).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 30).into(), 0).into(), "0xff".to_string()),
                    (
                        ((Any::advice(), 31).into(), 0).into(),
                        last_advice.to_string(),
                    ),
                ],
            }
        }

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                gen_errors(
                    1,
                    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "0xff"
                ),
                gen_errors(
                    2,
                    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "0xff"
                ),
                gen_errors(
                    3,
                    "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
                    "0xfe"
                )
            ])
        );
    }
}
