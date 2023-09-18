use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

use super::{
    big_uint_to_fp,
    utils::{poseidon_entry, poseidon_node},
};

#[derive(Clone, Debug)]
pub struct Node<const N_ASSETS: usize> {
    pub hash: Fp,
    pub balances: [Fp; N_ASSETS],
}
impl<const N_ASSETS: usize> Node<N_ASSETS> {
    /// Builds a "middle" (non-leaf-level) node of the MST
    pub fn middle(child_l: &Node<N_ASSETS>, child_r: &Node<N_ASSETS>) -> Node<N_ASSETS>
    where
        [usize; 2 * (1 + N_ASSETS)]: Sized,
    {
        let mut balances_sum = [Fp::zero(); N_ASSETS];
        for (i, balance) in balances_sum.iter_mut().enumerate() {
            *balance = child_l.balances[i] + child_r.balances[i];
        }

        Node {
            hash: poseidon_node(
                child_l.hash,
                child_l.balances,
                child_r.hash,
                child_r.balances,
            ),
            balances: balances_sum,
        }
    }

    /// Builds a leaf-level node of the MST
    pub fn leaf(username: &BigUint, balances: &[BigUint; N_ASSETS]) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        Node {
            hash: poseidon_entry::<N_ASSETS>(
                big_uint_to_fp(username),
                balances
                    .iter()
                    .map(big_uint_to_fp)
                    .collect::<Vec<Fp>>()
                    .try_into()
                    .unwrap(),
            ),
            //Map the array of balances using big_int_to_fp:
            balances: balances
                .iter()
                .map(big_uint_to_fp)
                .collect::<Vec<Fp>>()
                .try_into()
                .unwrap(),
        }
    }
}
