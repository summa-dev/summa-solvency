use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::merkle_sum_tree::utils::big_uint_to_fp;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

#[derive(Clone, Debug)]
pub struct Node<const N_ASSETS: usize> {
    pub hash: Fp,
    pub balances: [Fp; N_ASSETS],
}
impl<const N_ASSETS: usize> Node<N_ASSETS> {
    /// Builds a "middle" (non-leaf-level) node of the MST
    pub fn middle(child_l: &Node<N_ASSETS>, child_r: &Node<N_ASSETS>) -> Node<N_ASSETS>
    where
        [(); N_ASSETS + 2]: Sized,
    {
        let mut balances_sum = [Fp::zero(); N_ASSETS];
        for (i, balance) in balances_sum.iter_mut().enumerate() {
            *balance = child_l.balances[i] + child_r.balances[i];
        }

        Node {
            hash: Self::poseidon_hash_middle(balances_sum, child_l.hash, child_r.hash),
            balances: balances_sum,
        }
    }

    pub fn init_empty() -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        Node {
            hash: Fp::zero(),
            balances: [Fp::zero(); N_ASSETS],
        }
    }

    /// Builds a leaf-level node of the MST
    pub fn leaf(username: &BigUint, balances: &[BigUint; N_ASSETS]) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        Node {
            hash: Self::poseidon_hash_leaf(
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

    pub fn leaf_node_from_preimage(preimage: [Fp; N_ASSETS + 1]) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        Node {
            hash: Self::poseidon_hash_leaf(preimage[0], preimage[1..].try_into().unwrap()),
            balances: preimage[1..].try_into().unwrap(),
        }
    }

    pub fn middle_node_from_preimage(preimage: [Fp; N_ASSETS + 2]) -> Node<N_ASSETS>
    where
        [usize; N_ASSETS + 2]: Sized,
    {
        Node {
            hash: Self::poseidon_hash_middle(
                preimage[0..N_ASSETS].try_into().unwrap(),
                preimage[N_ASSETS],
                preimage[N_ASSETS + 1],
            ),
            balances: preimage[0..N_ASSETS].try_into().unwrap(),
        }
    }

    fn poseidon_hash_middle(
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

    fn poseidon_hash_leaf(username: Fp, balances: [Fp; N_ASSETS]) -> Fp
    where
        [usize; N_ASSETS + 1]: Sized,
    {
        let mut hash_inputs: [Fp; N_ASSETS + 1] = [Fp::zero(); N_ASSETS + 1];

        hash_inputs[0] = username;
        hash_inputs[1..N_ASSETS + 1].copy_from_slice(&balances);

        poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<{ N_ASSETS + 1 }>, 2, 1>::init()
            .hash(hash_inputs)
    }
}
