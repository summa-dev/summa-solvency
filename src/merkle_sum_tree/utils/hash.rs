use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::merkle_sum_tree::{L_ENTRY, L_NODE};
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

const WIDTH: usize = 7;
const RATE: usize = 6;

pub fn poseidon_node<const N_ASSETS: usize>(
    l1: Fp,
    l2: [Fp; N_ASSETS],
    r1: Fp,
    r2: [Fp; N_ASSETS],
) -> Fp {
    let mut hash_inputs: [Fp; L_NODE] = [Fp::zero(); L_NODE];

    hash_inputs[0] = l1;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&l2);
    hash_inputs[N_ASSETS + 1] = r1;
    hash_inputs[N_ASSETS + 2..2 * N_ASSETS + 2].copy_from_slice(&r2);

    poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<L_NODE>, WIDTH, RATE>::init()
        .hash(hash_inputs)
}

pub fn poseidon_entry<const N_ASSETS: usize>(left: Fp, right: [Fp; N_ASSETS]) -> Fp {
    let mut hash_inputs: [Fp; L_ENTRY] = [Fp::zero(); L_ENTRY];

    hash_inputs[0] = left;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&right);

    poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<L_ENTRY>, WIDTH, RATE>::init()
        .hash(hash_inputs)
}
