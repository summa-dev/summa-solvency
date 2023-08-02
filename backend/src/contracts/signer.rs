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
use std::{error::Error, fs::File, io::BufReader, path::Path, str::FromStr, sync::Arc};

#[derive(Debug)]
pub struct SummaSigner {
    signing_wallets: Vec<LocalWallet>,
    summa_contract: Summa<SignerMiddleware<Provider<Http>, LocalWallet>>,
}

impl SummaSigner {
    /// Creates a new SummaSigner instance
    /// # Arguments
    /// * `private_keys` - A list of the private keys of the accounts holding the exchange assets
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

        let provider = Provider::<Http>::try_from(rpc_url).unwrap();
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
        cex_addresses: Vec<ethers::types::H160>,
        cex_signatures: Vec<ethers::types::Bytes>,
        message: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let submit_proof_of_account_ownership_call = &self
            .summa_contract
            .submit_proof_of_account_ownership(cex_addresses, cex_signatures, message.to_owned());
        let tx = submit_proof_of_account_ownership_call.send().await.unwrap();

        tx.await.unwrap();

        Ok(())
    }

    pub async fn submit_proof_of_solvency(
        &self,
        erc_20_contract_addresses: Vec<ethers::types::H160>,
        balances_to_prove: Vec<ethers::types::U256>,
        mst_root: ethers::types::U256,
        proof: ethers::types::Bytes,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let submit_proof_of_solvency_call = &self.summa_contract.submit_proof_of_solvency(
            erc_20_contract_addresses,
            balances_to_prove,
            mst_root,
            proof,
        );
        let tx = submit_proof_of_solvency_call.send().await.unwrap();

        tx.await.unwrap();

        Ok(())
    }
}
