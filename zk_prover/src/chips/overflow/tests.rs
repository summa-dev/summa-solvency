use crate::chips::overflow::overflow_check::{OverflowCheckConfig, OverflowChip};
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};

use halo2_proofs::halo2curves::bn256::Fr as Fp;

#[derive(Debug, Clone)]
pub struct AddConfig {
    pub col_a: Column<Advice>,
    pub col_b: Column<Advice>,
    pub col_c: Column<Advice>,
    pub selector: Selector,
}

#[derive(Debug, Clone)]
pub struct AddChip {
    pub config: AddConfig,
}

impl AddChip {
    pub fn construct(config: AddConfig) -> Self {
        Self { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<Fp>) -> AddConfig {
        let col_a = meta.advice_column();
        let col_b = meta.advice_column();
        let col_c = meta.advice_column();
        let selector = meta.selector();
        // let instance = meta.instance_column();

        meta.enable_equality(col_a);
        meta.enable_equality(col_b);
        meta.enable_equality(col_c);
        // meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let s = meta.query_selector(selector);
            let a = meta.query_advice(col_a, Rotation::cur());
            let b = meta.query_advice(col_b, Rotation::cur());
            let c = meta.query_advice(col_c, Rotation::cur());
            vec![s * (a + b - c)]
        });

        AddConfig {
            col_a,
            col_b,
            col_c,
            selector,
            // instance,
        }
    }

    pub fn default(
        &self,
        a: Fp,
        b: Fp,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<
        (
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
            AssignedCell<Fp, Fp>,
        ),
        Error,
    > {
        layouter.assign_region(
            || "initialize value and sum",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let a_cell =
                    region.assign_advice(|| "a", self.config.col_a, 0, || Value::known(a))?;

                let b_cell =
                    region.assign_advice(|| "b", self.config.col_b, 0, || Value::known(b))?;

                let c_cell = region.assign_advice(
                    || "a + b",
                    self.config.col_c,
                    0,
                    || a_cell.value().copied() + b_cell.value(),
                )?;

                Ok((a_cell, b_cell, c_cell))
            },
        )
    }
}

#[derive(Debug, Clone)]
pub struct OverflowCheckTestConfig<const MAX_BITS: u8> {
    pub addchip_config: AddConfig,
    pub overflow_check_config: OverflowCheckConfig<MAX_BITS>,
}

#[derive(Default, Clone, Debug)]
struct OverflowCheckTestCircuit<const MAX_BITS: u8> {
    pub a: Fp,
    pub b: Fp,
}

impl<const MAX_BITS: u8> Circuit<Fp> for OverflowCheckTestCircuit<MAX_BITS> {
    type Config = OverflowCheckTestConfig<MAX_BITS>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        let addchip_config = AddChip::configure(meta);

        let a = meta.advice_column();
        meta.enable_equality(a);

        let b = meta.advice_column();

        let overflow_check_config = OverflowChip::<MAX_BITS>::configure(meta, a, b);

        {
            OverflowCheckTestConfig {
                addchip_config,
                overflow_check_config,
            }
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        // Initiate the add chip
        let addchip = AddChip::construct(config.addchip_config);
        let (a_cell, b_cell, c_cell) =
            addchip.default(self.a, self.b, layouter.namespace(|| "add chip"))?;

        // Initiate the overflow check chip
        let overflow_chip = OverflowChip::construct(config.overflow_check_config);
        overflow_chip.load(&mut layouter)?;

        // check overflow
        overflow_chip.assign(layouter.namespace(|| "checking overflow value a"), &a_cell)?;
        overflow_chip.assign(layouter.namespace(|| "checking overflow value b"), &b_cell)?;

        // to perform a + b as part of test
        overflow_chip.assign(
            layouter.namespace(|| "checking overflow value a + b"),
            &c_cell,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod testing {
    use super::OverflowCheckTestCircuit;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        halo2curves::bn256::Fr as Fp,
        plonk::Any,
    };

    #[test]
    fn test_overflow_250bits_case() {
        // 5 bits are optimal choices for 252 bits field
        // 32 ( = 1 << 5 ) fixed column for range check
        // 50 ( = 252 // 5 ) rows for decomposed column
        let k = 8;

        // In case, the left_balance(i.e user balance) is maximum value
        let a = Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]);
        let b = Fp::from(1);

        let circuit = OverflowCheckTestCircuit::<5> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        fn gen_errors(region_num: usize, last_advice: &str, advice: &str) -> VerifyFailure {
            VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (1, "equality check between decomposed_value and value").into(),
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
                        ((Any::advice(), 3).into(), 0).into(),
                        last_advice.to_string(),
                    ),
                    (((Any::advice(), 4).into(), 0).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 1).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 2).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 3).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 4).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 5).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 6).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 7).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 8).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 9).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 10).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 11).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 12).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 13).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 14).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 15).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 16).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 17).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 18).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 19).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 20).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 21).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 22).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 23).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 24).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 25).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 26).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 27).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 28).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 29).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 30).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 31).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 32).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 33).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 34).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 35).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 36).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 37).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 38).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 39).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 40).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 41).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 42).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 43).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 44).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 45).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 46).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 47).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 48).into(), advice.to_string()),
                    (((Any::advice(), 4).into(), 49).into(), advice.to_string()),
                ],
            }
        }
        assert_eq!(
            invalid_prover.verify(),
            Err(vec! {
                 gen_errors(2, "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "0x1f"),
                 gen_errors(4, "0x1000000000000000000000000000000000000000000000000000000000000000", "0"),
            })
        );
    }

    #[test]
    fn test_overflow_251bits_case_1() {
        let k = 13;

        // In case, the left_balance(i.e user balance) is maximum value
        let a = Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]);
        let b = Fp::from(1);

        let circuit = OverflowCheckTestCircuit::<12> { a, b };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (1, "equality check between decomposed_value and value").into(),
                    0,
                    ""
                )
                    .into(),
                location: FailureLocation::InRegion {
                    region: (4, "assign decomposed values").into(),
                    offset: 0
                },
                cell_values: vec![
                    (
                        ((Any::advice(), 3).into(), 0).into(),
                        "0x1000000000000000000000000000000000000000000000000000000000000000"
                            .to_string()
                    ),
                    (((Any::advice(), 4).into(), 0).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 1).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 2).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 3).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 4).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 5).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 6).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 7).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 8).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 9).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 10).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 11).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 12).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 13).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 14).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 15).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 16).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 17).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 18).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 19).into(), "0".to_string()),
                    (((Any::advice(), 4).into(), 20).into(), "0".to_string()),
                ]
            }])
        );
    }

    #[test]
    fn test_overflow_251bits_case_2() {
        let k = 9;

        //  left and right balance are equal to max value
        let max_balance = Fp::from_raw([
            0xffffffffffffffff,
            0xffffffffffffffff,
            0xffffffffffffffff,
            0x0fffffffffffffff,
        ]);

        let circuit = OverflowCheckTestCircuit::<8> {
            a: max_balance,
            b: max_balance,
        };
        let invalid_prover = MockProver::run(k, &circuit, vec![]).unwrap();

        fn gen_errors(region_num: usize, first_advice: &str, last_advice: &str) -> VerifyFailure {
            VerifyFailure::ConstraintNotSatisfied {
                constraint: (
                    (1, "equality check between decomposed_value and value").into(),
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
                        ((Any::advice(), 3).into(), 0).into(),
                        first_advice.to_string(),
                    ),
                    (((Any::advice(), 4).into(), 0).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 1).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 2).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 3).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 4).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 5).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 6).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 7).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 8).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 9).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 10).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 11).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 12).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 13).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 14).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 15).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 16).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 17).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 18).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 19).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 20).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 21).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 22).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 23).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 24).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 25).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 26).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 27).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 28).into(), "0xff".to_string()),
                    (((Any::advice(), 4).into(), 29).into(), "0xff".to_string()),
                    (
                        ((Any::advice(), 4).into(), 30).into(),
                        last_advice.to_string(),
                    ),
                ],
            }
        }

        assert_eq!(
            invalid_prover.verify(),
            Err(vec![
                gen_errors(
                    2,
                    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "0xff"
                ),
                gen_errors(
                    3,
                    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    "0xff"
                ),
                gen_errors(
                    4,
                    "0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
                    "0xfe"
                )
            ])
        );
    }
}
