//! An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
//! is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr as Fp,
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed},
};
use std::marker::PhantomData;

#[derive(Debug, Clone)]

/// Wrapper structure around Pow5Config which is the Poseidon Hash Configuration from halo2_gadgets.
///
/// Poseidon is a zk-friendly hash function.
///
/// # Type Parameters
///
/// * `WIDTH`: The width of the Poseidon permutation,
/// * `RATE`: The rate of the Poseidon permutation, typically WIDTH - 1.
/// * `L`: The length of the input array to the Poseidon hash function.
///
/// # Fields
///
/// * `pow5_config`: The configuration for the inner [halo2_gadgets::poseidon::Pow5Config]
pub struct PoseidonConfig<const WIDTH: usize, const RATE: usize, const L: usize> {
    pow5_config: Pow5Config<Fp, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

/// Chip that performs the Poseidon Hash
///
/// # Type Parameters
///
/// * `S`: The specification for the Poseidon hash function,
/// * `WIDTH`: The width of the Poseidon permutation,
/// * `RATE`: The rate of the Poseidon permutation, typically WIDTH - 1.
/// * `L`: The length of the input array to the Poseidon hash function.
pub struct PoseidonChip<
    S: Spec<Fp, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<S: Spec<Fp, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<S, WIDTH, RATE, L>
{
    /// Constructs a new Poseidon Chip given a PoseidonConfig
    pub fn construct(config: PoseidonConfig<WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    /// Configures the Poseidon Chip
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        state: [Column<Advice>; WIDTH],
        partial_sbox: Column<Advice>,
        rc_a: [Column<Fixed>; WIDTH],
        rc_b: [Column<Fixed>; WIDTH],
    ) -> PoseidonConfig<WIDTH, RATE, L> {
        let pow5_config = Pow5Chip::configure::<S>(meta, state, partial_sbox, rc_a, rc_b);

        PoseidonConfig { pow5_config }
    }

    /// Performs poseidon hash on the given input cells. Returns the output cell.
    pub fn hash(
        &self,
        mut layouter: impl Layouter<Fp>,
        input_cells: [AssignedCell<Fp, Fp>; L],
    ) -> Result<AssignedCell<Fp, Fp>, Error> {
        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), input_cells)
    }
}
