use crate::chips::poseidon::spec::{Spec2, Spec4};
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub fn poseidon_4(l1: Fp, l2: Fp, r1: Fp, r2: Fp) -> Fp {
    const WIDTH: usize = 5;
    const RATE: usize = 4;
    const L: usize = 4;

    poseidon::Hash::<Fp, Spec4, ConstantLength<L>, WIDTH, RATE>::init().hash([l1, l2, r1, r2])
}

pub fn poseidon_2(left: Fp, right: Fp) -> Fp {
    const WIDTH: usize = 3;
    const RATE: usize = 2;
    const L: usize = 2;

    poseidon::Hash::<Fp, Spec2, ConstantLength<L>, WIDTH, RATE>::init().hash([left, right])
}
