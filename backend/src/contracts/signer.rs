use crate::contracts::generated::summa_contract::Summa;
use ethers::{
    abi::{encode, Token},
    prelude::SignerMiddleware,
    providers::{Http, Provider},
    signers::{LocalWallet, Signer, WalletError},
    types::{Address, Signature},
    utils::keccak256,
};
use futures::future::join_all;
use serde_json::Value;
use std::{
    error::Error, fs::File, io::BufReader, path::Path, str::FromStr, sync::Arc, time::Duration,
};

use super::generated::summa_contract::{AddressOwnershipProof, Asset};

#[derive(Debug)]
pub struct SummaSigner {
    signing_wallets: Vec<LocalWallet>,
    summa_contract: Summa<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl SummaSigner {
    /// Creates a new SummaSigner instance
    /// # Arguments
    /// * `private_keys` - A list of the private keys of the addresses holding the exchange assets
    /// * `main_signer_key` - The private key of wallet that will interact with the chain on behalf of the exchange
    /// * `chain_id` - The chain id of the network
    /// * `rpc_url` - The RPC URL of the network
    /// * `address` - The address of the Summa contract
    pub fn new(
        private_keys: &[&str],
        main_signer_key: &str,
        chain_id: u64,
        rpc_url: &str,
        address: Address,
    ) -> Self {
        let wallet: LocalWallet = LocalWallet::from_str(main_signer_key).unwrap();

        let provider = Provider::<Http>::try_from(rpc_url)
            .unwrap()
            .interval(Duration::from_millis(10u64));
        let client = Arc::new(SignerMiddleware::new(
            provider,
            wallet.with_chain_id(chain_id),
        ));

        let contract = Summa::new(address, client);
        Self {
            signing_wallets: private_keys
                .iter()
                .map(|private_key| LocalWallet::from_str(private_key).unwrap())
                .collect(),
            summa_contract: contract,
        }
    }

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

    async fn sign_message(wallet: &LocalWallet, message: &str) -> Signature {
        let encoded_message = encode(&[Token::String(message.to_owned())]);
        let hashed_message = keccak256(encoded_message);
        wallet.sign_message(hashed_message).await.unwrap()
    }

    pub async fn generate_signatures(&self) -> Result<Vec<Signature>, WalletError> {
        let message = std::env::var("SIGNATURE_VERIFICATION_MESSAGE").unwrap();
        let signature_futures: Vec<_> = self
            .signing_wallets
            .iter()
            .map(|wallet| Self::sign_message(wallet, &message))
            .collect();

        Ok(join_all(signature_futures).await)
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

#[cfg(test)]
mod test {
    use super::*;
    use ethers::{types::Address, utils::Anvil};

    #[tokio::test]
    async fn test_sign_message() {
        let anvil = Anvil::new().spawn();

        let signer = SummaSigner::new(
            //Account #1
            &vec!["0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"],
            "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
            31337,
            anvil.endpoint().as_str(),
            //Verifier deployment is not necessary for this test
            Address::random(),
        );

        let signatures = signer.generate_signatures().await.unwrap();
        assert_eq!(signatures.len(), 1);
        //Signature produced by the account #1
        assert_eq!(signatures[0].to_string(), "089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b");
        drop(anvil);
    }
}
