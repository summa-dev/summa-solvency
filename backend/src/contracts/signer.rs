use crate::contracts::generated::summa_contract::Summa;
use ethers::{
    prelude::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
    types::Address,
};
use serde_json::Value;
use std::{
    error::Error, fs::File, io::BufReader, path::Path, str::FromStr, sync::Arc, time::Duration,
};

use super::generated::summa_contract::{AddressOwnershipProof, Asset};

#[derive(Debug)]
pub struct SummaSigner {
    summa_contract: Summa<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl SummaSigner {
    /// Creates a new SummaSigner instance
    /// # Arguments
    /// * `signer_key` - The private key of wallet that will interact with the chain on behalf of the exchange
    /// * `chain_id` - The chain id of the network
    /// * `rpc_url` - The RPC URL of the network
    /// * `address` - The address of the Summa contract
    pub fn new(signer_key: &str, chain_id: u64, rpc_url: &str, address: Address) -> Self {
        let wallet: LocalWallet = LocalWallet::from_str(signer_key).unwrap();

        let provider = Provider::<Http>::try_from(rpc_url)
            .unwrap()
            .interval(Duration::from_millis(10u64));
        let client = Arc::new(SignerMiddleware::new(
            provider,
            wallet.with_chain_id(chain_id),
        ));

        let contract = Summa::new(address, client);
        Self {
            summa_contract: contract,
        }
    }

    /*
    This method is never used. Can it be removed?
     */
    pub fn get_deployment_address<P: AsRef<Path>>(
        path: P,
        chain_id: u64,
    ) -> Result<Address, Box<dyn Error>> {
        // Open file in RO mode with buffer
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        // Read the JSON contents of the file
        let payload: Value = serde_json::from_reader(reader)?;

        // Retrieve the contract address from the deployments.json file
        let deployment_address: &Value = &payload.as_object().unwrap()
            [chain_id.to_string().as_str()]
        .as_object()
        .unwrap()["address"];

        let summa_address: &str = deployment_address.as_str().unwrap();

        let address: Address = summa_address.parse().unwrap();

        Ok(address)
    }

    pub async fn submit_proof_of_address_ownership(
        &self,
        address_ownership_proofs: Vec<AddressOwnershipProof>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let submit_proof_of_address_ownership = &self
            .summa_contract
            .submit_proof_of_address_ownership(address_ownership_proofs);
        let tx = submit_proof_of_address_ownership.send().await.unwrap();

        tx.await.unwrap();

        Ok(())
    }

    pub async fn submit_proof_of_solvency(
        &self,
        mst_root: ethers::types::U256,
        assets: Vec<Asset>,
        proof: ethers::types::Bytes,
        timestamp: ethers::types::U256,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let submit_proof_of_solvency_call = &self
            .summa_contract
            .submit_proof_of_solvency(mst_root, assets, proof, timestamp);
        let tx = submit_proof_of_solvency_call.send().await.unwrap();

        tx.await.unwrap();

        Ok(())
    }
}
