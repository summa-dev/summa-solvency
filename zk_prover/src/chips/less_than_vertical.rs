/* This is a 'vertical' implementation of LTChip
It reduces the number of advice columns present in the original 'horizontal approach */

use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    halo2curves::{bn256::Fr as Fp, ff::PrimeField},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, VirtualCells},
    poly::Rotation,
};

use gadgets::{
    bool_check,
    util::{expr_from_bytes, pow_of_two},
};

/// Instruction that the Lt vertical chip needs to implement.
pub trait LtVerticalInstruction {
    /// Assign the lhs and rhs witnesses to the Lt chip's region.
    fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        lhs: Value<Fp>,
        rhs: Value<Fp>,
    ) -> Result<(), Error>;

    /// Load the u8 lookup table.
    fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error>;
}

/// Config for the LtVertical chip.
#[derive(Clone, Copy, Debug)]
pub struct LtVerticalConfig<const N_BYTES: usize> {
    /// Denotes the lt outcome. If lhs < rhs then lt == 1, otherwise lt == 0.
    pub lt: Column<Advice>,
    /// Denotes the bytes representation of the difference between lhs and rhs.
    pub diff: Column<Advice>,
    /// Denotes the range within which each byte should lie.
    pub u8: Column<Fixed>,
    /// Denotes the range within which both lhs and rhs lie.
    pub range: Fp,
}

impl<const N_BYTES: usize> LtVerticalConfig<N_BYTES> {
    /// Returns an expression that denotes whether lhs < rhs, or not.
    pub fn is_lt(&self, meta: &mut VirtualCells<Fp>, rotation: Option<Rotation>) -> Expression<Fp> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }
}

/// Chip that compares lhs < rhs.
#[derive(Clone, Debug)]
pub struct LtVerticalChip<const N_BYTES: usize> {
    config: LtVerticalConfig<N_BYTES>,
}

impl<const N_BYTES: usize> LtVerticalChip<N_BYTES> {
    /// Configures the LtVertical chip.
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, Fp>) -> Expression<Fp>,
        lhs: impl FnOnce(&mut VirtualCells<Fp>) -> Expression<Fp>,
        rhs: impl FnOnce(&mut VirtualCells<Fp>) -> Expression<Fp>,
    ) -> LtVerticalConfig<N_BYTES> {
        let lt = meta.advice_column();
        let diff = meta.advice_column();
        let range = pow_of_two(N_BYTES * 8);
        let u8 = meta.fixed_column();

        meta.create_gate("lt gate", |meta| {
            let q_enable = q_enable(meta);
            let lt = meta.query_advice(lt, Rotation::cur());

            let mut diff_bytes = Vec::<Expression<Fp>>::new();

            diff_bytes.push(meta.query_advice(diff, Rotation::cur()));
            diff_bytes.push(meta.query_advice(diff, Rotation::next()));

            for i in 2..N_BYTES {
                diff_bytes.push(meta.query_advice(diff, Rotation(i as i32)));
            }

            let check_a =
                lhs(meta) - rhs(meta) - expr_from_bytes(&diff_bytes) + (lt.clone() * range);

            let check_b = bool_check(lt);

            [check_a, check_b]
                .into_iter()
                .map(move |poly| q_enable.clone() * poly)
        });

        meta.annotate_lookup_any_column(u8, || "LOOKUP_u8");

        meta.lookup_any("range check for u8", |meta| {
            let u8_cell = meta.query_advice(diff, Rotation::cur());
            let u8_range = meta.query_fixed(u8, Rotation::cur());
            vec![(u8_cell, u8_range)]
        });

        meta.lookup_any("range check for u8", |meta| {
            let u8_cell = meta.query_advice(diff, Rotation::next());
            let u8_range = meta.query_fixed(u8, Rotation::cur());
            vec![(u8_cell, u8_range)]
        });

        for i in 0..N_BYTES {
            meta.lookup_any("range check for u8", |meta| {
                let u8_cell = meta.query_advice(diff, Rotation(i as i32));
                let u8_range = meta.query_fixed(u8, Rotation::cur());
                vec![(u8_cell, u8_range)]
            });
        }

        LtVerticalConfig {
            lt,
            diff,
            range,
            u8,
        }
    }

    /// Constructs a Lt chip given a config.
    pub fn construct(config: LtVerticalConfig<N_BYTES>) -> LtVerticalChip<N_BYTES> {
        LtVerticalChip { config }
    }
}

impl<const N_BYTES: usize> LtVerticalInstruction for LtVerticalChip<N_BYTES> {
    fn assign(
        &self,
        region: &mut Region<'_, Fp>,
        offset: usize,
        lhs: Value<Fp>,
        rhs: Value<Fp>,
    ) -> Result<(), Error> {
        let config = self.config();

        let lt = lhs.zip(rhs).map(|(lhs, rhs)| lhs < rhs);

        region.assign_advice(
            || "lt chip: lt",
            config.lt,
            offset,
            || lt.map(|lt| Fp::from(lt as u64)),
        )?;

        let diff_bytes = lhs.zip(rhs).map(|(lhs, rhs)| {
            let mut diff = lhs - rhs;
            let lt = lhs < rhs;
            if lt {
                diff += config.range;
            } else {
                diff += Fp::zero();
            }
            diff.to_repr()
        });

        for idx in 0..N_BYTES {
            region.assign_advice(
                || format!("lt chip: diff byte {}", idx),
                config.diff,
                offset + idx,
                || diff_bytes.as_ref().map(|bytes| Fp::from(bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }

    fn load(&self, layouter: &mut impl Layouter<Fp>) -> Result<(), Error> {
        const RANGE: usize = 256;

        layouter.assign_region(
            || "load u8 range check table",
            |mut region| {
                for i in 0..RANGE {
                    region.assign_fixed(
                        || "assign cell in fixed column",
                        self.config.u8,
                        i,
                        || Value::known(Fp::from(i as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }
}

impl<const N_BYTES: usize> Chip<Fp> for LtVerticalChip<N_BYTES> {
    type Config = LtVerticalConfig<N_BYTES>;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

//TODO: Tests - our use case is for N = 248 BITS (31 Bytes)
