use crate::apis::csv_parser::parse_csv_to_assets;
use num_bigint::BigInt;
use std::collections::HashMap;

use snark_verifier_sdk::{
    evm::gen_evm_proof_shplonk, gen_pk, halo2::gen_snark_shplonk, CircuitExt,
};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{keygen_pk, keygen_vk, Circuit, ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
};

use summa_solvency::{
    circuits::{
        aggregation::WrappedAggregationCircuit,
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{full_prover, generate_setup_params},
    },
    merkle_sum_tree::{Entry, MerkleSumTree},
};

const LEVELS: usize = 4;
const L: usize = 2 + (N_ASSETS * 2);
const K: u32 = 11;
const N_BYTES: usize = 31; // 248 / 8
const N_ASSETS: usize = 2;

#[derive(Debug)]
struct SnapshotData<const N_ASSETS: usize> {
    exchange_id: String,
    commit_hash: Fp,                          // May change type later
    entries: HashMap<usize, Entry<N_ASSETS>>, // TODO: change to `HashMap<Name, Entry<N_ASSETS>>`
    assets: Vec<Asset>,
    user_proofs: Option<HashMap<Name, InclusionProof<N_ASSETS>>>,
    on_chain_proof: Option<Vec<u8>>,
}

type Name = String;

#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub pubkeys: Vec<String>,
    pub balances: Vec<BigInt>,
    pub signature: Vec<String>,
}

#[derive(Debug)]
struct InclusionProof<const N_ASSETS: usize> {
    leaf_hash: Fp,
    balances: [BigInt; N_ASSETS],
    vk: Vec<u8>,
    proof: Vec<u8>,
}

impl<const N_ASSETS: usize> SnapshotData<N_ASSETS> {
    pub fn new(
        exchange_id: &str,
        entry_csv: &str,
        asset_csv: &str,
    ) -> Result<SnapshotData<N_ASSETS>, Box<dyn std::error::Error>> {
        let assets = parse_csv_to_assets(asset_csv).unwrap();
        let mst = MerkleSumTree::<N_ASSETS>::new(entry_csv).unwrap();

        let entries = mst
            .entries()
            .into_iter()
            .enumerate()
            .map(|(i, entry)| (i, entry.clone()))
            .collect::<HashMap<usize, Entry<N_ASSETS>>>();

        let root_node = mst.root();

        Ok(SnapshotData {
            exchange_id: exchange_id.to_owned(),
            commit_hash: root_node.hash,
            entries,
            assets,
            user_proofs: None,
            on_chain_proof: None,
        })
    }

    fn get_mst_circuit(
        params: ParamsKZG<Bn256>,
        user_index: usize,
    ) -> (
        MstInclusionCircuit<LEVELS, L, N_ASSETS>,
        VerifyingKey<G1Affine>,
        ProvingKey<G1Affine>,
    ) {
        let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let inclusion_circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init(
            "src/apis/csv/entry_16.csv", // TODO: optimize this, inefficient to read from file again
            user_index,
        );

        return (inclusion_circuit, vk, pk);
    }

    fn get_solvency_circuit(
        params: ParamsKZG<Bn256>,
    ) -> (SolvencyCircuit<L, 2, N_BYTES>, ProvingKey<G1Affine>) {
        let circuit = SolvencyCircuit::<L, N_ASSETS, N_BYTES>::init_empty();

        let assets_sum = [Fp::from(556863u64), Fp::from(556863u64)]; // TODO: get from self.assets

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        // Only now we can instantiate the circuit with the actual inputs
        let solvency_circuit =
            SolvencyCircuit::<L, 2, N_BYTES>::init("src/apis/csv/entry_16.csv", assets_sum); // TODO: get file path from struct or else

        return (solvency_circuit, pk);
    }

    fn generate_agg_circuit(&mut self) -> (WrappedAggregationCircuit<2>, ParamsKZG<Bn256>) {
        // TODO: make it background running in future task
        // we generate a universal trusted setup of our own for testing
        let params_agg = generate_setup_params(23);

        // downsize params for our application specific snark
        let mut params_app = params_agg.clone();
        params_app.downsize(K);

        // solvency proof
        let (solvency_circuit, solvency_pk) = Self::get_solvency_circuit(params_app.clone());

        // user proof
        let (mst_inclusion_circuit, _, user_pk) = Self::get_mst_circuit(params_app.clone(), 0);

        let snark_app = [
            gen_snark_shplonk(&params_app, &user_pk, mst_inclusion_circuit, None::<&str>),
            gen_snark_shplonk(&params_app, &solvency_pk, solvency_circuit, None::<&str>),
        ];

        // Generate proof for aggregated circuit
        let agg_circuit = WrappedAggregationCircuit::<2>::new(&params_agg, snark_app);
        (agg_circuit, params_agg)
    }

    #[cfg(feature = "testing")]
    pub fn generate_proofs(&mut self) {
        // Skip generate recursive proof
        let params_app = generate_setup_params(11);
        let mut user_proofs = HashMap::<String, InclusionProof<N_ASSETS>>::new();
        let (circuit, vk, pk) = Self::get_mst_circuit(params_app.clone(), 0);

        let proof = full_prover(&params_app, &pk, circuit.clone(), circuit.instances());
        let user_instance = circuit.instances()[0].clone();

        if let Some(entry) = self.entries.get(&0) {
            user_proofs.insert(
                entry.username().to_owned(),
                InclusionProof::<N_ASSETS> {
                    leaf_hash: user_instance[0],
                    balances: entry.balances().clone(),
                    vk: vk.to_bytes(halo2_proofs::SerdeFormat::RawBytes),
                    proof,
                },
            );
        }

        // for testing results
        self.user_proofs = Some(user_proofs);
        self.on_chain_proof = Some(vec![16u8; 8]);
    }

    #[cfg(not(feature = "testing"))]
    pub fn generate_proofs(&mut self) {
        // Generate proof for aggregated circuit
        let (agg_circuit, params_agg) = self.generate_agg_circuit();
        let pk_agg = gen_pk(&params_agg, &agg_circuit.without_witnesses(), None);
        let instances = agg_circuit.instances();

        let proof_calldata =
            gen_evm_proof_shplonk(&params_agg, &pk_agg, agg_circuit, instances.clone());
        self.on_chain_proof = Some(proof_calldata);

        // Initialize variable for user proofs
        let mut user_proofs = HashMap::<String, InclusionProof<N_ASSETS>>::new();

        // Generate proofs for ueers
        let params_app = generate_setup_params(11);
        for i in 0..self.entries.len() {
            let (circuit, vk, pk) = Self::get_mst_circuit(params_app.clone(), i);

            let proof = full_prover(&params_app, &pk, circuit.clone(), circuit.instances());

            let user_instance = circuit.instances()[0].clone();

            if let Some(entry) = self.entries.get(&i) {
                user_proofs.insert(
                    entry.username().to_owned(),
                    InclusionProof::<N_ASSETS> {
                        leaf_hash: user_instance[0],
                        balances: entry.balances().clone(),
                        vk: vk.to_bytes(halo2_proofs::SerdeFormat::RawBytes),
                        proof,
                    },
                );
            }
        }

        self.user_proofs = Some(user_proofs);
    }

    pub fn get_user_proof(&self, name: &str) -> Result<&InclusionProof<N_ASSETS>, &'static str> {
        match &self.user_proofs {
            Some(user_proofs) => match user_proofs.get(name) {
                Some(proof) => Ok(proof),
                None => Err("User proof not found"),
            },
            None => Err("User proofs not initialized"),
        }
    }

    pub fn get_onchain_proof(&self) -> Result<Vec<u8>, &'static str> {
        match &self.on_chain_proof {
            Some(proof) => Ok(proof.clone()),
            None => Err("on-chain proof not initialized"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_data_initialization() {
        let entry_csv = "src/apis/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";
        let snapshot_data = SnapshotData::<2>::new("CEX_1", entry_csv, asset_csv).unwrap();

        // Check assets
        assert!(snapshot_data.assets[0].name.contains(&"eth".to_string()));
        assert!(snapshot_data.assets[1].name.contains(&"dai".to_string()));
        assert!(snapshot_data.assets[0].balances[0] == BigInt::from(1500u32));
        assert!(snapshot_data.assets[0].balances[1] == BigInt::from(2500u32));
    }

    #[test]
    fn test_snapshot_data_generate_proof() {
        let entry_csv = "src/apis/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";
        let mut snapshot_data = SnapshotData::<2>::new("CEX_1", entry_csv, asset_csv).unwrap();

        assert!(snapshot_data.user_proofs.is_none());
        assert!(snapshot_data.on_chain_proof.is_none());
        let empty_on_chain_proof = snapshot_data.get_onchain_proof();
        assert_eq!(empty_on_chain_proof, Err("on-chain proof not initialized"));

        snapshot_data.generate_proofs();

        //  Check the proof for the user at index 0
        let user_proof = snapshot_data.get_user_proof("dxGaEAii");
        assert!(user_proof.is_ok());

        //  Check the proof for last user
        let none_user_proof = snapshot_data.get_user_proof("AtwIxZHo");
        assert!(none_user_proof.is_err());

        // Check updated on-chain proof
        let on_chain_proof = snapshot_data.get_onchain_proof();
        assert_eq!(on_chain_proof.is_ok(), true);
    }
}
