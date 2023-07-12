use halo2_proofs::halo2curves::bn256::Fr as Fp;

use crate::merkle_sum_tree::utils::hash::poseidon_node;
use crate::merkle_sum_tree::Node;

pub fn create_middle_node<const N_ASSETS: usize>(
    child_l: &Node<N_ASSETS>,
    child_r: &Node<N_ASSETS>,
) -> Node<N_ASSETS>
where
    [(); 2 * (1 + N_ASSETS)]: Sized,
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
