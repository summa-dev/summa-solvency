/*
An easy-to-use implementation of the Poseidon Hash in the form of a Halo2 Chip. While the Poseidon Hash function
is already implemented in halo2_gadgets, there is no wrapper chip that makes it easy to use in other circuits.
*/

// This chip adds a set of advice columns to the gadget Chip to store the inputs of the hash
// compared to `hash_with_instance` this version doesn't use any instance column.

use halo2_gadgets::poseidon::{primitives::*, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{arithmetic::FieldExt, circuit::*, plonk::*};
use std::marker::PhantomData;

#[derive(Debug, Clone)]

// WIDTH, RATE and L are const generics for the struct, which represent the width, rate, and number of inputs for the Poseidon hash function, respectively.
// This means they are values that are known at compile time and can be used to specialize the implementation of the struct.
// The actual chip provided by halo2_gadgets is added to the parent Chip.
pub struct PoseidonConfig<F: FieldExt, const WIDTH: usize, const RATE: usize, const L: usize> {
    pow5_config: Pow5Config<F, WIDTH, RATE>,
}

#[derive(Debug, Clone)]

pub struct PoseidonChip<
    F: FieldExt,
    S: Spec<F, WIDTH, RATE>,
    const WIDTH: usize,
    const RATE: usize,
    const L: usize,
> {
    config: PoseidonConfig<F, WIDTH, RATE, L>,
    _marker: PhantomData<S>,
}

impl<F: FieldExt, S: Spec<F, WIDTH, RATE>, const WIDTH: usize, const RATE: usize, const L: usize>
    PoseidonChip<F, S, WIDTH, RATE, L>
{
    pub fn construct(config: PoseidonConfig<F, WIDTH, RATE, L>) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    // Configuration of the PoseidonChip
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        hash_inputs: Vec<Column<Advice>>,
    ) -> PoseidonConfig<F, WIDTH, RATE, L> {
        let partial_sbox = meta.advice_column();
        let rc_a = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();
        let rc_b = (0..WIDTH).map(|_| meta.fixed_column()).collect::<Vec<_>>();

        for i in 0..WIDTH {
            meta.enable_equality(hash_inputs[i]);
        }
        meta.enable_constant(rc_b[0]);

        let pow5_config = Pow5Chip::configure::<S>(
            meta,
            hash_inputs.try_into().unwrap(),
            partial_sbox,
            rc_a.try_into().unwrap(),
            rc_b.try_into().unwrap(),
        );

        PoseidonConfig {
            pow5_config,
        }
    }

    // L is the number of inputs to the hash function
    // Takes the cells containing the input values of the hash function and return the cell containing the hash output
    // It uses the pow5_chip to compute the hash
    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        input_cells: [AssignedCell<F, F>; L],
    ) -> Result<AssignedCell<F, F>, Error> {

        let pow5_chip = Pow5Chip::construct(self.config.pow5_config.clone());

        // initialize the hasher
        let hasher = Hash::<_, _, S, ConstantLength<L>, WIDTH, RATE>::init(
            pow5_chip,
            layouter.namespace(|| "hasher"),
        )?;
        hasher.hash(layouter.namespace(|| "hash"), input_cells)
    }

}
