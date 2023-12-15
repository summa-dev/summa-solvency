use crate::chips::poseidon::poseidon_spec::PoseidonSpec;
use crate::merkle_sum_tree::utils::big_uint_to_fp;
use halo2_gadgets::poseidon::primitives::{self as poseidon, ConstantLength};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use num_bigint::BigUint;

#[derive(Clone, Debug, PartialEq)]
pub struct Node<const N_CURRENCIES: usize> {
    pub hash: Fp,
    pub balances: [Fp; N_CURRENCIES],
}
impl<const N_CURRENCIES: usize> Node<N_CURRENCIES> {
    /// Builds a leaf-level node of the MST
    /// The leaf node hash is equal to `H(username, balance[0], balance[1], ... balance[N_CURRENCIES - 1])`
    /// The balances are equal to `balance[0], balance[1], ... balance[N_CURRENCIES - 1]`
    pub fn leaf(username: &BigUint, balances: &[BigUint; N_CURRENCIES]) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        let mut hash_preimage = [Fp::zero(); N_CURRENCIES + 1];
        hash_preimage[0] = big_uint_to_fp(username);
        for (i, balance) in hash_preimage.iter_mut().enumerate().skip(1) {
            *balance = big_uint_to_fp(&balances[i - 1]);
        }

        Node::leaf_node_from_preimage(&hash_preimage)
    }

    /// Builds a "middle" (non-leaf-level) node of the MST
    /// The middle node hash is equal to `H(LeftChild.balance[0] + RightChild.balance[0], LeftChild.balance[1] + RightChild.balance[1], ..., LeftChild.balance[N_CURRENCIES - 1] + RightChild.balance[N_CURRENCIES - 1], LeftChild.hash, RightChild.hash)`
    /// The balances are equal to `LeftChild.balance[0] + RightChild.balance[0], LeftChild.balance[1] + RightChild.balance[1], ..., LeftChild.balance[N_CURRENCIES - 1] + RightChild.balance[N_CURRENCIES - 1]`
    pub fn middle(child_l: &Node<N_CURRENCIES>, child_r: &Node<N_CURRENCIES>) -> Node<N_CURRENCIES>
    where
        [(); N_CURRENCIES + 2]: Sized,
    {
        let mut hash_preimage = [Fp::zero(); N_CURRENCIES + 2];
        for (i, balance) in hash_preimage.iter_mut().enumerate().take(N_CURRENCIES) {
            *balance = child_l.balances[i] + child_r.balances[i];
        }
        hash_preimage[N_CURRENCIES] = child_l.hash;
        hash_preimage[N_CURRENCIES + 1] = child_r.hash;

        Node::middle_node_from_preimage(&hash_preimage)
    }

    /// Returns an empty node where the hash is 0 and the balances are all 0
    pub fn init_empty() -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        Node {
            hash: Fp::zero(),
            balances: [Fp::zero(); N_CURRENCIES],
        }
    }

    pub fn leaf_node_from_preimage(preimage: &[Fp; N_CURRENCIES + 1]) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        Node {
            hash: Self::poseidon_hash_leaf(preimage[0], preimage[1..].try_into().unwrap()),
            balances: preimage[1..].try_into().unwrap(),
        }
    }

    /// Builds a middle-level node of the MST
    /// The hash preimage must be equal to `LeftChild.balance[0] + RightChild.balance[0], LeftChild.balance[1] + RightChild.balance[1], ..., LeftChild.balance[N_CURRENCIES - 1] + RightChild.balance[N_CURRENCIES - 1], LeftChild.hash, RightChild.hash`
    /// The balances are equal to `LeftChild.balance[0] + RightChild.balance[0], LeftChild.balance[1] + RightChild.balance[1], ..., LeftChild.balance[N_CURRENCIES - 1] + RightChild.balance[N_CURRENCIES - 1]`
    pub fn middle_node_from_preimage(preimage: &[Fp; N_CURRENCIES + 2]) -> Node<N_CURRENCIES>
    where
        [usize; N_CURRENCIES + 2]: Sized,
    {
        Node {
            hash: Self::poseidon_hash_middle(
                preimage[0..N_CURRENCIES].try_into().unwrap(),
                preimage[N_CURRENCIES],
                preimage[N_CURRENCIES + 1],
            ),
            balances: preimage[0..N_CURRENCIES].try_into().unwrap(),
        }
    }

    fn poseidon_hash_middle(
        balances_sum: [Fp; N_CURRENCIES],
        hash_child_left: Fp,
        hash_child_right: Fp,
    ) -> Fp
    where
        [usize; N_CURRENCIES + 2]: Sized,
    {
        let mut hash_inputs: [Fp; N_CURRENCIES + 2] = [Fp::zero(); N_CURRENCIES + 2];

        hash_inputs[0..N_CURRENCIES].copy_from_slice(&balances_sum);
        hash_inputs[N_CURRENCIES] = hash_child_left;
        hash_inputs[N_CURRENCIES + 1] = hash_child_right;

        poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<{ N_CURRENCIES + 2 }>, 2, 1>::init()
            .hash(hash_inputs)
    }

    fn poseidon_hash_leaf(username: Fp, balances: [Fp; N_CURRENCIES]) -> Fp
    where
        [usize; N_CURRENCIES + 1]: Sized,
    {
        let mut hash_inputs: [Fp; N_CURRENCIES + 1] = [Fp::zero(); N_CURRENCIES + 1];

        hash_inputs[0] = username;
        hash_inputs[1..N_CURRENCIES + 1].copy_from_slice(&balances);

        poseidon::Hash::<Fp, PoseidonSpec, ConstantLength<{ N_CURRENCIES + 1 }>, 2, 1>::init()
            .hash(hash_inputs)
    }
}
