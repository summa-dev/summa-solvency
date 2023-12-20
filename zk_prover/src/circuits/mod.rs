pub mod merkle_sum_tree;
mod tests;
pub mod traits;
pub mod types;
pub mod utils;

use halo2_proofs::halo2curves::bn256::Fr as Fp;

pub trait WithInstances {
    fn num_instances(&self) -> usize;
    fn instances(&self) -> Vec<Vec<Fp>>;
}
