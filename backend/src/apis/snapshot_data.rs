use num_bigint::BigInt;
use std::collections::HashMap;
use std::{fs::File, io::BufReader};

use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
    SerdeFormat::RawBytes,
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

struct MstParamsAndKeys<const LEVELS: usize, const L: usize, const N_ASSETS: usize> {
    params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
    vk: VerifyingKey<G1Affine>,
}

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
    asset_signatures: AssetSignatures,
    mst_params_and_keys: MstParamsAndKeys<LEVELS, L, N_ASSETS>,
    proofs_of_inclusions: HashMap<u64, UserProof>,
    proof_of_solvency: Option<SolvencyProof<N_ASSETS>>,
}

#[derive(Debug, Clone)]
pub struct Asset {
    pub name: String,
    pub pubkeys: Vec<String>,
    pub balances: Vec<BigInt>,
    pub sum_balances: Fp,
}

pub type AssetSignatures = HashMap<String, String>;

#[derive(Debug, Clone)]
struct UserProof {
    // for each user
    leaf_hash: Fp,
    proof: Vec<u8>,
}

pub struct InclusionProof {
    // public inputs
    leaf_hash: Fp,
    root_hash: Fp,
    // need for verification
    vk: VerifyingKey<G1Affine>,
    pk: ProvingKey<G1Affine>,
    proof: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SolvencyProof<const N_ASSETS: usize> {
    // public inputs
    root_hash: Fp,
    assets_sum: [Fp; N_ASSETS],
    // need for verification
    // vk is already exist in the onchain verifier
    pk: ProvingKey<G1Affine>,
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
        inclusion_pk_path: Option<&str>,
    ) -> Result<SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K>, Box<dyn std::error::Error>> {
        let (assets, signatures) = parse_csv_to_assets(asset_csv).unwrap();
        let mst: MerkleSumTree<N_ASSETS> = MerkleSumTree::<N_ASSETS>::new(entry_csv).unwrap();

        let user_proofs = HashMap::<u64, UserProof>::new();

        // generate params and plonk keys for mst inclusion proof
        let circuit = MstInclusionCircuit::<LEVELS, L, N_ASSETS>::init_empty();
        let params = generate_setup_params(K);

        if let Some(pk_path) = inclusion_pk_path {
            let pk_file = File::open(pk_path)?;
            let mut reader = BufReader::new(pk_file);
            let pk = ProvingKey::<G1Affine>::read::<_, MstInclusionCircuit<LEVELS, L, N_ASSETS>>(
                &mut reader,
                RawBytes,
            )?;
            let vk = pk.get_vk().clone();

            return Ok(SnapshotData {
                exchange_id: exchange_id.to_owned(),
                mst,
                assets,
                asset_signatures: signatures,
                mst_params_and_keys: MstParamsAndKeys { params, pk, vk },
                proofs_of_inclusions: user_proofs,
                proof_of_solvency: None,
            });
        }

        let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
        let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

        Ok(SnapshotData {
            exchange_id: exchange_id.to_owned(),
            mst,
            assets,
            asset_signatures: signatures,
            mst_params_and_keys: MstParamsAndKeys { params, pk, vk },
            proofs_of_inclusions: user_proofs,
            proof_of_solvency: None,
        })
    }

    fn generate_inclusion_proof(&self, user_index: usize) -> Result<UserProof, &'static str> {
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
        let proof = full_prover(
            &self.mst_params_and_keys.params,
            &self.mst_params_and_keys.pk,
            circuit,
            instances.clone(),
        );

        Ok(UserProof {
            leaf_hash: instances[0][0],
            proof,
        })
    }

    pub fn generate_solvency_proof(&mut self, pk_path: &str) -> Result<(), &'static str> {
        if self.proof_of_solvency.is_some() {
            return Err("Solvency proof already exists");
        }

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
        let params = generate_setup_params(10);

        let f = File::open(pk_path).unwrap();
        let mut reader = BufReader::new(f);
        let pk = ProvingKey::<G1Affine>::read::<_, SolvencyCircuit<L, N_ASSETS, N_BYTES>>(
            &mut reader,
            RawBytes,
        )
        .unwrap();

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
            root_hash: self.mst.root().hash, // equivalant to instances[0]
            assets_sum,                      // equivalant to instances[1]
            pk: pk.clone(),
            proof: full_prover(&params, &pk, circuit.clone(), instances),
        });

        Ok(())
    }

    pub fn get_user_proof(&mut self, user_index: u64) -> Result<InclusionProof, &'static str> {
        let user_proof = self.proofs_of_inclusions.get(&user_index);
        match user_proof {
            Some(user_proof) => Ok(InclusionProof {
                leaf_hash: user_proof.leaf_hash,
                root_hash: self.mst.root().hash,
                vk: self.mst_params_and_keys.vk.clone(),
                pk: self.mst_params_and_keys.pk.clone(),
                proof: user_proof.proof.clone(),
            }),
            None => {
                let user_proof =
                    Self::generate_inclusion_proof(&self, user_index as usize).unwrap();
                self.proofs_of_inclusions
                    .insert(user_index, user_proof.clone());
                Ok(InclusionProof {
                    leaf_hash: user_proof.leaf_hash,
                    root_hash: self.mst.root().hash,
                    vk: self.mst_params_and_keys.vk.clone(),
                    pk: self.mst_params_and_keys.pk.clone(),
                    proof: user_proof.proof,
                })
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
    const N_BYTES: usize = 64 / 8;
    const K: u32 = 11;

    fn initialize_snapshot_data(
        load_existing_inclusion_pk: Option<bool>,
    ) -> SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K> {
        let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
        let asset_csv = "src/apis/csv/assets_2.csv";

        if load_existing_inclusion_pk == Some(true) {
            return SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new(
                "CEX_1",
                entry_csv,
                asset_csv,
                Some("artifacts/mst_inclusion_4_6_2.pk"),
            )
            .unwrap();
        }
        SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new("CEX_1", entry_csv, asset_csv, None)
            .unwrap()
    }

    #[test]
    fn test_snapshot_data_initialization() {
        let snapshot_data = initialize_snapshot_data(None);

        // Check assets
        assert!(snapshot_data.assets[0].name.contains(&"eth".to_string()));
        assert!(snapshot_data.assets[1].name.contains(&"dai".to_string()));
        assert!(snapshot_data.assets[0].balances[0] == BigInt::from(1500u32));
        assert!(snapshot_data.assets[0].balances[1] == BigInt::from(2500u32));
    }

    #[test]
    fn test_snapshot_data_generate_solvency_proof() {
        let proving_key_path = "artifacts/solvency_6_2_8.pk";
        let mut snapshot_data = initialize_snapshot_data(None);

        assert!(snapshot_data.proof_of_solvency.is_none());
        let empty_on_chain_proof = snapshot_data.get_onchain_proof();
        assert!(empty_on_chain_proof.is_err());

        let result = snapshot_data.generate_solvency_proof(proving_key_path);
        assert_eq!(result.is_ok(), true);

        // Check updated on-chain proof
        let on_chain_proof = snapshot_data.get_onchain_proof();
        assert_eq!(on_chain_proof.is_ok(), true);
    }

    #[test]
    fn test_snapshot_data_generate_inclusion_proof() {
        let mut snapshot_data = initialize_snapshot_data(None);

        assert_eq!(snapshot_data.proofs_of_inclusions.len(), 0);

        // Check updated on-chain proof
        let user_proof = snapshot_data.get_user_proof(0);
        assert!(user_proof.is_ok());
        assert_eq!(snapshot_data.proofs_of_inclusions.len(), 1);
    }

    #[test]
    fn test_snapshot_data_generate_inclusion_proof_with_external_proving_key() {
        let mut snapshot_data = initialize_snapshot_data(Some(bool::from(true)));

        assert_eq!(snapshot_data.proofs_of_inclusions.len(), 0);

        // Check updated on-chain proof
        let user_proof = snapshot_data.get_user_proof(0);
        assert!(user_proof.is_ok());
        assert_eq!(snapshot_data.proofs_of_inclusions.len(), 1);
    }

    #[test]
    fn test_snapshot_data_stored_asset_data() {
        let snapshot_data = initialize_snapshot_data(None);

        for asset in snapshot_data.assets {
            for address in asset.pubkeys {
                assert!(snapshot_data.asset_signatures.get(&address).is_some());
            }
        }
        assert!(snapshot_data
            .asset_signatures
            .get("0x0000000000000000000000000000000000000000")
            .is_none());
    }
}
