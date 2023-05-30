use crate::{
    chips::poseidon::spec::MySpec,
    merkle_sum_tree::{POSEIDON_LENGTH, POSEIDON_RATE, POSEIDON_WIDTH},
};
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn poseidon<const N_ASSETS: usize>(
    l1: Fp,
    l2: [Fp; N_ASSETS],
    r1: Fp,
    r2: [Fp; N_ASSETS],
) -> Fp {
    let mut hash_inputs: [Fp; POSEIDON_LENGTH] = [Fp::zero(); POSEIDON_LENGTH];

    hash_inputs[0] = l1;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&l2);
    hash_inputs[N_ASSETS + 1] = r1;
    hash_inputs[N_ASSETS + 2..2 * N_ASSETS + 2].copy_from_slice(&r2);

    poseidon::Hash::<
        Fp,
        MySpec,
        ConstantLength<POSEIDON_LENGTH>,
        POSEIDON_WIDTH,
        POSEIDON_RATE,
    >::init()
    .hash(hash_inputs)
}
