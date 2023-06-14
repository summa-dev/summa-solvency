use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr as Fp,
    plonk::{Column, ConstraintSystem, Error, Instance},
};
use snark_verifier_sdk::halo2::aggregation::AggregationConfig;

/// Wrapper around AggregationConfig that adds a vector of instance columns. Specifically an instance column for each input SNARK.
#[derive(Clone)]
pub struct WrappedAggregationConfig<const N_SNARK: usize> {
    pub aggregation_config: AggregationConfig,
    pub instances: [Column<Instance>; N_SNARK],
}

impl<const N_SNARK: usize> WrappedAggregationConfig<N_SNARK> {
    pub fn configure(
        meta: &mut ConstraintSystem<Fp>,
        composition_bits: Vec<usize>,
        overflow_bits: Vec<usize>,
    ) -> Self {
        let instances = [(); N_SNARK].map(|_| meta.instance_column());

        for instance in instances.iter() {
            meta.enable_equality(*instance);
        }

        // Note that the aggregation config is configured after having configured the instances. Therefore, the instance column of the aggregation circuit is the last one
        let aggregation_config =
            AggregationConfig::configure(meta, composition_bits, overflow_bits);

        Self {
            aggregation_config,
            instances,
        }
    }

    // Enforce copy constraint check between input cell and instance column at row passed as input
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<Fp>,
        cell: &AssignedCell<Fp, Fp>,
        instance: Column<Instance>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), instance, row)
    }
}
