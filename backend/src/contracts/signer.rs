use ethers::{
    prelude::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{Address, U256},
};
use serde_json::Value;
use std::{error::Error, fs::File, io::BufReader, path::Path, str::FromStr, sync::Arc};
use tokio::sync::Mutex;

use super::generated::summa_contract::{AddressOwnershipProof, Cryptocurrency};
use crate::contracts::generated::summa_contract::Summa;

pub enum AddressInput {
    Address(Address),
    Path(String),
}

#[derive(Debug)]
pub struct SummaSigner {
    nonce_lock: Mutex<()>, // To prevent running `submit` methods concurrently
    summa_contract: Summa<SignerMiddleware<Arc<Provider<Http>>, LocalWallet>>,
}

impl SummaSigner {
    /// Creates a new SummaSigner instance
    /// # Arguments
    /// * `signer_key` - The private key of wallet that will interact with the chain on behalf of the exchange
    /// * `url` -  The endpoint for connecting to the node
    /// * `address` - The address of the Summa contract
    pub async fn new(
        signer_key: &str,
        url: &str,
        address_input: AddressInput,
    ) -> Result<Self, Box<dyn Error>> {
        let wallet: LocalWallet = LocalWallet::from_str(signer_key).unwrap();

        let provider = Arc::new(Provider::try_from(url)?);
        let chain_id = provider.get_chainid().await?.as_u64();
        let client = Arc::new(SignerMiddleware::new(
            provider,
            wallet.with_chain_id(chain_id),
        ));

        let address = match address_input {
            AddressInput::Address(address) => address,
            AddressInput::Path(path) => {
                let address = Self::get_deployment_address(path, chain_id).unwrap();
                address
            }
        };

        Ok(Self {
            nonce_lock: Mutex::new(()),
            summa_contract: Summa::new(address, client),
        })
    }

    pub fn get_summa_address(&self) -> Address {
        self.summa_contract.address()
    }

    fn get_deployment_address<P: AsRef<Path>>(
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
        let lock_guard = self.nonce_lock.lock().await;

        let submit_proof_of_address_ownership = &self
            .summa_contract
            .submit_proof_of_address_ownership(address_ownership_proofs);

        // To prevent nonce collision, we lock the nonce before sending the transaction
        let tx = submit_proof_of_address_ownership.send().await?;

        // Wait for the pending transaction to be mined
        tx.await?;

        drop(lock_guard);
        Ok(())
    }

    pub async fn submit_commitment(
        &self,
        mst_root: U256,
        root_sums: Vec<U256>,
        cryptocurrencies: Vec<Cryptocurrency>,
        timestamp: U256,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let lock_guard = self.nonce_lock.lock().await;

        let submit_liability_commitment = &self.summa_contract.submit_commitment(
            mst_root,
            root_sums,
            cryptocurrencies,
            timestamp,
        );

        // To prevent nonce collision, we lock the nonce before sending the transaction
        let tx = submit_liability_commitment.send().await?;

        // Wait for the pending transaction to be mined
        tx.await?;

        drop(lock_guard);

        Ok(())
    }
}
