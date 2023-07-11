//! This is a 'vertical' implementation of LTChip
//! It reduces the number of advice columns present in the original 'horizontal approach' available in the zkevm gadgets.

use halo2_proofs::{
    circuit::{Chip, Layouter, Region, Value},
    halo2curves::{bn256::Fr as Fp, ff::PrimeField},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector, VirtualCells},
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
    /// Denotes the selector used to enable the lookup check
    pub lookup_enable: Selector,
}

impl<const N_BYTES: usize> LtVerticalConfig<N_BYTES> {
    /// Returns an expression that denotes whether lhs < rhs, or not.
    pub fn is_lt(&self, meta: &mut VirtualCells<Fp>, rotation: Option<Rotation>) -> Expression<Fp> {
        meta.query_advice(self.lt, rotation.unwrap_or_else(Rotation::cur))
    }
}

/// Chip that compares lhs < rhs. It performs the following constraints:
///
/// * `lhs - rhs - diff_bytes + lt * range = 0`. When q_enable is 1, this constraint is enforced.
/// * `lt * (lt - 1) = 0`, i.e. lt is either 0 or 1. When q_enable is 1, this constraint is enforced.
/// * `diff(cur)` ∈ to `u8` lookup table. Namely `decomposed_value` should be in the `MAX_BITS` range. When q_enable is 1, this constraint is enforced.

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
        lt: Column<Advice>,
        diff: Column<Advice>,
        u8: Column<Fixed>,
        lookup_enable: Selector,
    ) -> LtVerticalConfig<N_BYTES> {
        let range = pow_of_two(N_BYTES * 8);

        meta.create_gate("lt gate", |meta| {
            let q_enable = q_enable(meta);
            let lt = meta.query_advice(lt, Rotation::cur());

            let diff_bytes: Vec<Expression<Fp>> = (0..N_BYTES)
                .map(|i| meta.query_advice(diff, Rotation(i as i32)))
                .collect();

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
            let lookup_enable = meta.query_selector(lookup_enable);
            vec![(lookup_enable * u8_cell, u8_range)]
        });

        LtVerticalConfig {
            lt,
            diff,
            range,
            u8,
            lookup_enable,
        }
    }

    /// Constructs a Lt chip given a config.
    pub fn construct(config: LtVerticalConfig<N_BYTES>) -> LtVerticalChip<N_BYTES> {
        LtVerticalChip { config }
    }
}

impl<const N_BYTES: usize> LtVerticalInstruction for LtVerticalChip<N_BYTES> {
    /// From lhs and rhs values, assigns `lt` and `diff_bytes` to the region.
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
            config.lookup_enable.enable(region, idx)?;

            region.assign_advice(
                || format!("lt chip: diff byte {}", idx),
                config.diff,
                offset + idx,
                || diff_bytes.as_ref().map(|bytes| Fp::from(bytes[idx] as u64)),
            )?;
        }

        Ok(())
    }

    /// Loads the lookup table for `u8` range check.
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
