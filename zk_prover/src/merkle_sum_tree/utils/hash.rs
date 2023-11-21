use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn poseidon_node<const N_ASSETS: usize>(
    balances_sum: [Fp; N_ASSETS],
    hash_child_left: Fp,
    hash_child_right: Fp,
) -> Fp
where
    [usize; N_ASSETS + 2]: Sized,
{
    let mut hash_inputs: [Fp; N_ASSETS + 2] = [Fp::zero(); N_ASSETS + 2];

    hash_inputs[0..N_ASSETS].copy_from_slice(&balances_sum);
    hash_inputs[N_ASSETS] = hash_child_left;
    hash_inputs[N_ASSETS + 1] = hash_child_right;

    poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<{ N_ASSETS + 2 }>, 2, 1>::init()
        .hash(hash_inputs)
}

pub fn poseidon_entry<const N_ASSETS: usize>(left: Fp, right: [Fp; N_ASSETS]) -> Fp
where
    [usize; N_ASSETS + 1]: Sized,
{
    let mut hash_inputs: [Fp; N_ASSETS + 1] = [Fp::zero(); N_ASSETS + 1];

    hash_inputs[0] = left;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&right);

    poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<{ N_ASSETS + 1 }>, 2, 1>::init()
        .hash(hash_inputs)
}
