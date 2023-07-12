use crate::contracts::generated::summa_contract::{ProofOfSolvencySubmittedFilter, Summa};
use ethers::{
    abi::{encode, Token},
    prelude::{
        k256::{schnorr::SigningKey, Secp256k1},
        stream::EventStream,
        ContractError, Event, SignerMiddleware,
    },
    providers::{FilterWatcher, Http, Provider, StreamExt},
    signers::{LocalWallet, Signer, Wallet, WalletError},
    types::{Address, Log, Signature},
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
    pub fn initialize(
        private_keys: Vec<&str>,
        main_signer_key: &str,
        chain_id: u64,
        rpc_url: &str,
        address: Address,
    ) -> Result<SummaSigner, WalletError> {
        let wallet: LocalWallet = LocalWallet::from_str(&main_signer_key).unwrap();

        let provider = Provider::<Http>::try_from(rpc_url).unwrap();
        let client = SignerMiddleware::new(provider, wallet.with_chain_id(chain_id));
        let client2 = Arc::new(client);

        // An example of how to retrieve the contract address from the deployments.json file
        // let payload = Self::read_payload_from_file("./src/contracts/deployments.json").unwrap();
        // let deployment_address: &Value = &payload.as_object().unwrap()
        //     [chain_id.to_string().as_str()]
        // .as_object()
        // .unwrap()["address"];

        // let summa_address: &str = deployment_address.as_str().unwrap();

        // let address: Address = summa_address.parse().unwrap();

        let contract = Summa::new(address, client2);
        Ok(SummaSigner {
            signing_wallets: private_keys
                .iter()
                .map(|private_key| LocalWallet::from_str(&private_key).unwrap())
                .collect(),
            summa_contract: contract,
        })
    }

    fn read_payload_from_file<P: AsRef<Path>>(path: P) -> Result<Value, Box<dyn Error>> {
        // Open file in RO mode with buffer
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        // Read the JSON contents of the file
        let u: Value = serde_json::from_reader(reader)?;

        Ok(u)
    }

    async fn sign_message(wallet: &LocalWallet, exchange_id: &str) -> Signature {
        let encoded_message = encode(&[
            Token::String("Summa proof of solvency for ".to_owned()),
            Token::String(exchange_id.to_owned()),
        ]);
        let hashed_message = keccak256(encoded_message);
        wallet.sign_message(hashed_message).await.unwrap()
    }

    pub async fn generate_signatures(
        &self,
        exchange_id: &str,
    ) -> Result<Vec<Signature>, WalletError> {
        let signature_futures: Vec<_> = self
            .signing_wallets
            .iter()
            .map(|wallet| Self::sign_message(wallet, exchange_id))
            .collect();

        Ok(join_all(signature_futures).await)
    }

    pub async fn submitProofOfSolvency(
        &self,
        exchange_id: String,
        cex_addresses: Vec<ethers::types::H160>,
        cex_signatures: Vec<ethers::types::Bytes>,
        erc_20_contract_addresses: Vec<ethers::types::H160>,
        balances_to_prove: Vec<ethers::types::U256>,
        mst_root: ethers::types::U256,
        proof: ethers::types::Bytes,
    ) {
        let result = self
            .summa_contract
            .submit_proof_of_solvency(
                exchange_id,
                cex_addresses,
                cex_signatures,
                erc_20_contract_addresses,
                balances_to_prove,
                mst_root,
                proof,
            )
            .await
            .unwrap_err();

        println!("{:?}", result.decode_revert::<String>().unwrap());
    }
}
