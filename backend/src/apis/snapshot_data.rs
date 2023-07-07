use num_bigint::BigInt;
use std::collections::HashMap;

use halo2_proofs::{
    halo2curves::bn256::Fr as Fp,
    plonk::{keygen_pk, keygen_vk},
};
use snark_verifier_sdk::CircuitExt;

use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{full_prover, generate_setup_params},
    },
    merkle_sum_tree::utils::big_int_to_fp,
    merkle_sum_tree::MerkleSumTree,
};

use crate::apis::csv_parser::parse_csv_to_assets;

struct SnapshotData<
    const LEVELS: usize,
    const L: usize,
    const N_ASSETS: usize,
    const N_BYTES: usize,
    const K: u32,
> {
    exchange_id: String,
    mst: MerkleSumTree<N_ASSETS>,
    assets: Vec<Asset>,
    proofs_of_inclusions: HashMap<u64, InclusionProof>,
    proof_of_solvency: Option<SolvencyProof<N_ASSETS>>,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub pubkeys: Vec<String>,
    pub balances: Vec<BigInt>,
    pub sum_balances: Fp,
    pub signatures: Vec<String>,
}

#[derive(Debug, Clone)]
struct InclusionProof {
    // public input
    leaf_hash: Fp,
    vk: Vec<u8>,
    proof: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SolvencyProof<const N_ASSETS: usize> {
    // public inputs
    penultimate_node_hash: [Fp; 2],
    assets_sum: [Fp; N_ASSETS],
    proof: Vec<u8>,
}

impl<
        const LEVELS: usize,
        const L: usize,
        const N_ASSETS: usize,
        const N_BYTES: usize,
        const K: u32,
    > SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K>
{
    pub fn new(
        exchange_id: &str,
        entry_csv: &str,
        asset_csv: &str,
    ) -> Result<SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K>, Box<dyn std::error::Error>> {
        let assets = parse_csv_to_assets(asset_csv).unwrap();
        let mst: MerkleSumTree<N_ASSETS> = MerkleSumTree::<N_ASSETS>::new(entry_csv).unwrap();

        let user_proofs = HashMap::<u64, InclusionProof>::new();

        Ok(SnapshotData {
            exchange_id: exchange_id.to_owned(),
            mst,
            assets,
            proofs_of_inclusions: user_proofs,
            proof_of_solvency: None,
        })
    }

    fn generate_inclusion_proof(&self, user_index: usize) -> Result<InclusionProof, &'static str> {
        // TODO: fetch pk from outside. For now, we generate them here
        let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();
        let params = generate_setup_params(K);

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let proof = self.mst.generate_proof(user_index).unwrap();

        let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS> {
            leaf_hash: proof.entry.compute_leaf().hash,
            leaf_balances: proof
                .entry
                .balances()
                .iter()
                .map(big_int_to_fp)
                .collect::<Vec<_>>(),
            path_element_hashes: proof.sibling_hashes,
            path_element_balances: proof.sibling_sums,
            path_indices: proof.path_indices,
            root_hash: proof.root_hash,
        };

        let instances = circuit.instances().clone();
        let proof = full_prover(&params, &pk, circuit.clone(), instances.clone());

        Ok(InclusionProof {
            leaf_hash: instances[0][0],
            vk: vk.to_bytes(halo2_proofs::SerdeFormat::RawBytes),
            proof,
        })
    }

    pub fn generate_solvency_proof(&mut self) -> Result<(), &'static str> {
        // Prepare public inputs for solvency
        let mut assets_sum = [Fp::from(0u64); N_ASSETS];
        let asset_names = self
            .assets
            .iter()
            .map(|asset| asset.name.clone())
            .collect::<Vec<String>>();

        for asset in &self.assets {
            let index = asset_names.iter().position(|x| *x == asset.name).unwrap();
            assets_sum[index] = asset.sum_balances;
        }

        // generate solvency proof
        // TODO: fetch pk from outside. For now, we generate them here
        let circuit = SolvencyCircuit::<L, N_ASSETS, N_BYTES>::init_empty();
        let params = generate_setup_params(K);

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        let (penultimate_node_left, penultimate_node_right) = &self
            .mst
            .penultimate_level_data()
            .expect("Failed to retrieve penultimate level data");

        let circuit = SolvencyCircuit::<L, N_ASSETS, N_BYTES> {
            left_node_hash: penultimate_node_left.hash,
            left_node_balances: penultimate_node_left.balances,
            right_node_hash: penultimate_node_right.hash,
            right_node_balances: penultimate_node_right.balances,
            assets_sum,
            root_hash: self.mst.root().hash,
        };

        let instances = circuit.instances();

        self.proof_of_solvency = Some(SolvencyProof::<N_ASSETS> {
            penultimate_node_hash: [instances[0][0], instances[0][1]],
            assets_sum,
            proof: full_prover(&params, &pk, circuit.clone(), instances),
        });

        Ok(())
    }

    pub fn get_user_proof(&mut self, user_index: u64) -> Result<InclusionProof, &'static str> {
        let user_proof = self.proofs_of_inclusions.get(&user_index);
        match user_proof {
            Some(proof) => Ok(proof.clone()),
            None => {
                let user_proof =
                    Self::generate_inclusion_proof(&self, user_index as usize).unwrap();
                self.proofs_of_inclusions
                    .insert(user_index, user_proof.clone());
                Ok(user_proof)
            }
        }
    }

    pub fn get_onchain_proof(&self) -> Result<SolvencyProof<N_ASSETS>, &'static str> {
        match &self.proof_of_solvency {
            Some(proof) => Ok(proof.clone()),
            None => Err("on-chain proof not initialized"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N_ASSETS: usize = 2;
    const L: usize = 2 + (N_ASSETS * 2);
    const LEVELS: usize = 4;
    const N_BYTES: usize = 31;
    const K: u32 = 11;

    fn initiate_snapshot_data() -> SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K> {
        let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";
        SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new("CEX_1", entry_csv, asset_csv).unwrap()
    }

    #[test]
    fn test_snapshot_data_initialization() {
        let snapshot_data = initiate_snapshot_data();

        // Check assets
        assert!(snapshot_data.assets[0].name.contains(&"eth".to_string()));
        assert!(snapshot_data.assets[1].name.contains(&"dai".to_string()));
        assert!(snapshot_data.assets[0].balances[0] == BigInt::from(1500u32));
        assert!(snapshot_data.assets[0].balances[1] == BigInt::from(2500u32));
    }

    #[test]
    fn test_snapshot_data_generate_solvency_proof() {
        let mut snapshot_data = initiate_snapshot_data();

        assert!(snapshot_data.proof_of_solvency.is_none());
        let empty_on_chain_proof = snapshot_data.get_onchain_proof();
        assert!(empty_on_chain_proof.is_err());

        let result = snapshot_data.generate_solvency_proof();
        assert_eq!(result.is_ok(), true);

        // Check updated on-chain proof
        let on_chain_proof = snapshot_data.get_onchain_proof();
        assert_eq!(on_chain_proof.is_ok(), true);
    }

    #[test]
    fn test_snapshot_data_generate_inclusion_proof() {
        let mut snapshot_data = initiate_snapshot_data();

        assert_eq!(snapshot_data.proofs_of_inclusions.len(), 0);

        // Check updated on-chain proof
        let user_proof = snapshot_data.get_user_proof(0);
        assert!(user_proof.is_ok());
        assert_eq!(snapshot_data.proofs_of_inclusions.len(), 1);
    }
}
