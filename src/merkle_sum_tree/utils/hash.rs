use crate::chips::poseidon::spec_entry::MySpec as PoseidonSpecEntry;
use crate::chips::poseidon::spec_node::MySpec as PoseidonSpecNode;
use crate::merkle_sum_tree::{R_L_ENTRY, R_L_NODE, WIDTH_ENTRY, WIDTH_NODE};
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn poseidon_node<const N_ASSETS: usize>(
    l1: Fp,
    l2: [Fp; N_ASSETS],
    r1: Fp,
    r2: [Fp; N_ASSETS],
) -> Fp {
    let mut hash_inputs: [Fp; R_L_NODE] = [Fp::zero(); R_L_NODE];

    hash_inputs[0] = l1;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&l2);
    hash_inputs[N_ASSETS + 1] = r1;
    hash_inputs[N_ASSETS + 2..2 * N_ASSETS + 2].copy_from_slice(&r2);

    poseidon::Hash::<Fp, PoseidonSpecNode, ConstantLength<R_L_NODE>, WIDTH_NODE, R_L_NODE>::init()
        .hash(hash_inputs)
}

pub fn poseidon_entry<const N_ASSETS: usize>(left: Fp, right: [Fp; N_ASSETS]) -> Fp {
    let mut hash_inputs: [Fp; R_L_ENTRY] = [Fp::zero(); R_L_ENTRY];

    hash_inputs[0] = left;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&right);

    poseidon::Hash::<Fp, PoseidonSpecEntry, ConstantLength<R_L_ENTRY>, WIDTH_ENTRY, R_L_ENTRY>::init(
    )
    .hash(hash_inputs)
}
