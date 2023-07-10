use crate::apis::snapshot_data::SnapshotData;
use std::fmt;

use super::snapshot_data::InclusionProof;

#[derive(Debug)]
pub enum SnapshotError {
    Error(String),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::Error(msg) => write!(f, "{}", msg),
            _ => write!(f, "Unknown error"),
        }
    }
}

pub struct Snapshot<
    const LEVELS: usize,
    const L: usize,
    const N_ASSETS: usize,
    const N_BYTES: usize,
    const K: u32,
> {
    exchange_id: String,
    status: SnapshotStatus,
    // signer: SummaSigner,
    pub round_info: RoundInfo,
    pub data: Option<SnapshotData<LEVELS, L, N_ASSETS, N_BYTES, K>>,
}

#[derive(Debug, PartialEq)]
enum SnapshotStatus {
    Initialized,
    MSTGenerated,
    ProofsGenerated,
    ProofOfSolvencySubmitted,
}

#[derive(Debug)]
pub struct RoundInfo {
    pub contract_address: String,
    pub exchange_id: String,
    pub mst_root: Vec<u8>,
}

impl<
        const LEVELS: usize,
        const L: usize,
        const N_ASSETS: usize,
        const N_BYTES: usize,
        const K: u32,
    > Snapshot<LEVELS, L, N_ASSETS, N_BYTES, K>
{
    pub fn new(
        exchange_id: &str,
        contract_address: &str,
        // signer: SummaSigner,
    ) -> Self {
        Snapshot {
            exchange_id: exchange_id.to_string(),
            status: SnapshotStatus::Initialized,
            // signer,
            round_info: RoundInfo {
                contract_address: contract_address.to_string(),
                exchange_id: exchange_id.to_string(),
                mst_root: vec![0], // maybe we can use None here
            },
            data: None,
        }
    }

    pub fn init_data(&mut self, entry_csv: &str, asset_csv: &str) -> Result<(), SnapshotError> {
        // Check status if it is initialized return error
        if self.status != SnapshotStatus::Initialized {
            return Err(SnapshotError::Error(
                "Snapshot data already initialized".to_string(),
            ));
        }

        self.data = Some(
            SnapshotData::<LEVELS, L, N_ASSETS, N_BYTES, K>::new(
                &self.exchange_id,
                entry_csv,
                asset_csv,
                Some(&format!(
                    "artifacts/mst_inclusion_{}_{}_{}.pk",
                    LEVELS, L, N_ASSETS
                )),
            )
            .unwrap(),
        );
        self.status = SnapshotStatus::MSTGenerated;

        match &self.data {
            Some(data) => {
                self.round_info.mst_root = data.get_root_hash().to_vec();
                Ok(())
            }
            None => Err(SnapshotError::Error(
                "Snapshot data not initialized".to_string(),
            )),
        }
    }

    pub fn generate_proof(&mut self) -> Result<(), SnapshotError> {
        if let Some(data) = &mut self.data {
            data.generate_solvency_proof(&format!(
                "artifacts/solvency_{}_{}_{}.pk",
                L, N_ASSETS, N_BYTES
            ))
            .unwrap();
            self.status = SnapshotStatus::ProofsGenerated;
            Ok(())
        } else {
            Err(SnapshotError::Error(
                "Snapshot data not initialized".to_string(),
            ))
        }
    }

    pub fn verify_onchain_proof(&self) -> Result<(), SnapshotError> {
        if self.status == SnapshotStatus::ProofOfSolvencySubmitted {
            SnapshotError::Error("Solvency proof already submitted".to_string());
        }

        if self.status == SnapshotStatus::ProofsGenerated {
            match &self.data {
                Some(data) => {
                    let _solvency_proof = data.get_onchain_proof();
                    // TODO: Integate SummaSigner, and send it to onchain verifier
                    // self.signer.send_proof(solvency_proof);
                    Ok(())
                }
                None => Err(SnapshotError::Error(
                    "Snapshot data not initialized".to_string(),
                )),
            }
        } else {
            Err(SnapshotError::Error(
                "Solvency proof is not ready".to_string(),
            ))
        }
    }

    pub fn get_user_proof(&mut self, user_index: u64) -> Result<InclusionProof, &'static str> {
        let user_proof = self.data.as_mut().unwrap().get_user_proof(user_index)?;
        println!("user_proof: {:?}", user_proof.get_leaf_hash());
        Ok(user_proof)
    }
}
