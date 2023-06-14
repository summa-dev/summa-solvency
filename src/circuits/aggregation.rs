use crate::chips::aggregation::WrappedAggregationConfig;
use ecc::integer::rns::Rns;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner},
    halo2curves::bn256::{Bn256, Fq, Fr as Fp},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::kzg::commitment::ParamsKZG,
};
use itertools::Itertools;
use maingate::{MainGateInstructions, RangeInstructions};
use snark_verifier_sdk::{
    halo2::aggregation::AggregationCircuit, CircuitExt, Snark, BITS, LIMBS, SHPLONK,
};

/// Wrapper around Aggregation Circuit. It contains a vector of vectors `prev_instances`. Each inner vector represent the instance of an input snark.
/// For example, if the input snarks are 2 and the instances are [0x11, 0xbb, ...] and [0x22, 0xcc, ...], then prev_instances is [[0x11, 0xbb, ...], [0x22, 0xcc, ...]]
#[derive(Clone)]
pub struct WrappedAggregationCircuit<const N_SNARK: usize> {
    aggregation_circuit: AggregationCircuit<SHPLONK>,
    prev_instances: Vec<Vec<Fp>>,
}

impl<const N_SNARK: usize> WrappedAggregationCircuit<N_SNARK> {
    pub fn new(params: &ParamsKZG<Bn256>, snarks: impl IntoIterator<Item = Snark>) -> Self {
        let snarks = snarks.into_iter().collect_vec();

        let prev_instances: Vec<Vec<Fp>> = snarks
            .iter()
            .flat_map(|snark| snark.instances.iter())
            .cloned() // need to clone it because otherwise I would be collecting references to the instances
            .collect_vec();

        let aggregation_circuit = AggregationCircuit::new(params, snarks);

        Self {
            aggregation_circuit,
            prev_instances,
        }
    }
}

impl<const N_SNARK: usize> Circuit<Fp> for WrappedAggregationCircuit<N_SNARK> {
    type Config = WrappedAggregationConfig<N_SNARK>;
    type FloorPlanner = SimpleFloorPlanner;
    #[cfg(feature = "halo2_circuit_params")]
    type Params = ();

    fn without_witnesses(&self) -> Self {
        let aggregation_circuit = AggregationCircuit::without_witnesses(&self.aggregation_circuit);

        let prev_instances: Vec<Vec<Fp>> = vec![Vec::new(); N_SNARK];

        Self {
            aggregation_circuit,
            prev_instances,
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fp>) -> Self::Config {
        WrappedAggregationConfig::configure(
            meta,
            vec![BITS / LIMBS],
            Rns::<Fq, Fp, LIMBS, BITS>::construct().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fp>,
    ) -> Result<(), Error> {
        let main_gate = config.aggregation_config.main_gate();
        let range_chip = config.aggregation_config.range_chip();
        range_chip.load_table(&mut layouter)?;

        let (accumulator_limbs, prev_instances) = self
            .aggregation_circuit
            .aggregation_region(config.clone().aggregation_config, &mut layouter)?;

        for (row, limb) in accumulator_limbs.into_iter().enumerate() {
            main_gate.expose_public(layouter.namespace(|| ""), limb, row)?;
        }

        // expose the instances from the input snarks to the public
        for (prev_instance, instance) in prev_instances.iter().zip(config.instances.iter()) {
            for (row, cell) in prev_instance.iter().enumerate() {
                config.expose_public(layouter.namespace(|| ""), cell, *instance, row)?;
            }
        }

        Ok(())
    }
}

impl<const N_SNARK: usize> CircuitExt<Fp> for WrappedAggregationCircuit<N_SNARK> {
    // for a case of 2 snarks input with 1 instance column each with 4 rows, it should be [4, 4, 16]. Where 16 are `num_instance` from the aggregation circuit
    fn num_instance(&self) -> Vec<usize> {
        let mut num_instance = self
            .prev_instances
            .iter()
            .map(|instance| instance.len())
            .collect_vec();

        num_instance.push(self.aggregation_circuit.num_instance()[0]);

        num_instance
    }

    // following the previous example, it should be like [[0x001, 0x111, 0xaaa, 0xbbb], [0xaaa, 0xfff, 0xeee, 0x111], [0x11, 0xbb, ...]]. Note that the last vector is the instance of the aggregation circuit
    fn instances(&self) -> Vec<Vec<Fp>> {
        let mut instances = self.prev_instances.clone();
        instances.push(self.aggregation_circuit.instances()[0].clone());
        instances
    }
}
