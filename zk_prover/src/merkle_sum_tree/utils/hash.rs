use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn poseidon_node<const N_ASSETS: usize>(
    l1: Fp,
    l2: [Fp; N_ASSETS],
    r1: Fp,
    r2: [Fp; N_ASSETS],
) -> Fp
where
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    let mut hash_inputs: [Fp; 2 * (1 + N_ASSETS)] = [Fp::zero(); 2 * (1 + N_ASSETS)];

    hash_inputs[0] = l1;
    hash_inputs[1..N_ASSETS + 1].copy_from_slice(&l2);
    hash_inputs[N_ASSETS + 1] = r1;
    hash_inputs[N_ASSETS + 2..2 * N_ASSETS + 2].copy_from_slice(&r2);

    poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<{ 2 * (1 + N_ASSETS) }>, 2, 1>::init()
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
