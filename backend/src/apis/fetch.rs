// use base64::encode;
use std::{error::Error, marker::PhantomData, str::FromStr, sync::Arc};

use ethers::{
    abi::Address,
    contract::{builders::ContractCall, Contract, ContractError},
    prelude::{FunctionCall, SignerMiddleware},
    providers::{Http, Middleware, Provider, StreamExt},
    signers::{LocalWallet, Signer},
    types::{Bytes, U256},
};
use halo2_proofs::halo2curves::bn256::Fr as Fp;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE};
use serde::Deserialize;

use crate::contracts;
use contracts::generated::mock_erc20::MockERC20;

#[derive(Deserialize, Debug)]
/// This is the root level of the JSON response. It contains a data field, which corresponds to the "data" field in the JSON.
struct Response {
    data: Data,
}
/// This struct represents the "data" field of the JSON. It contains an items field, which corresponds to the "items" array in the JSON.
#[derive(Deserialize, Debug)]
struct Data {
    items: Vec<Item>,
}

/// This struct represents each object in the "items" array. It contains a balance field and a contract_address field. These fields correspond to the "balance" and "contract_address" fields in each item of the "items" array in the JSON.
#[derive(Deserialize, Debug)]
struct Item {
    balance: String,
    contract_address: String,
}

pub trait BalanceFromContract<M: Middleware> {
    fn get_balance_from_contract(&self, account: Address) -> FunctionCall<Arc<M>, M, U256>;
}

fn update_balance(mut accumulator: Fp, balance: U256) -> Fp {
    let mut u8_balance = [0u8; 32];
    balance.to_little_endian(&mut u8_balance);
    accumulator += Fp::from_bytes(&u8_balance).unwrap();
    accumulator
}

/// This function takes a list of token contracts, an address and returns the balances of that address for the queried contracts.
async fn fetch_balances_per_addr<'a, M: Middleware + 'a>(
    client: SignerMiddleware<Provider<Http>, LocalWallet>,
    contracts: Vec<Box<dyn BalanceFromContract<M> + Send>>,
    asset_addresses: Vec<&'a str>,
) -> Result<Vec<Fp>, Box<dyn Error>> {
    // TODO: client connection check before fetching.
    let mut result: Vec<Fp> = Vec::new();

    // First fetch eth balance over all addresses
    let mut sum_eth_balance = Fp::zero();

    for address in asset_addresses.clone() {
        let addr = Address::from_str(address).unwrap();
        let eth_balance: U256 = client.get_balance(addr, None).await.unwrap();
        sum_eth_balance = update_balance(sum_eth_balance, eth_balance);
    }
    result.push(sum_eth_balance);

    // Most in case, the number of contracts is less than the number of asset addresses
    // Iterating over contracts first is more efficient
    let mut sum_erc_balance = Fp::zero();
    for contract in &contracts {
        for address in asset_addresses.clone() {
            let addr = Address::from_str(address).unwrap();
            let erc_balance = contract
                .get_balance_from_contract(addr)
                .call()
                .await
                .unwrap();
            sum_erc_balance = update_balance(sum_erc_balance, erc_balance);
        }
        result.push(sum_erc_balance)
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fetch_asset_sums() {
        // Have to implement `get_erc20_balance` for `contracts` input in `fetch_balances_per_addr`
        impl<M: Middleware> BalanceFromContract<M> for MockERC20<M> {
            fn get_balance_from_contract(&self, account: Address) -> FunctionCall<Arc<M>, M, U256> {
                self.balance_of(account)
            }
        }

        let private_key =
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string();
        let provider_url = "http://localhost:8545".to_string();

        let wallet: LocalWallet = LocalWallet::from_str(&private_key).unwrap();
        let provider = Provider::<Http>::try_from(provider_url).unwrap();

        let client = SignerMiddleware::new(provider, wallet.with_chain_id(31337u32));
        let mock_erc_20_address =
            Address::from_str("0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0").unwrap();
        let mock_erc_20_contract = MockERC20::new(mock_erc_20_address, Arc::new(client.clone()));

        // Each account has 185621 wei(total eth balance sum divided by 3)
        // 0x90F79bf6EB2c4f870365E785982E1f101E93b906 has 164236 MockERC20 Token
        let addresses = vec![
            "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
            "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
            "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
        ];

        let asset_sums =
            fetch_balances_per_addr(client, vec![Box::new(mock_erc_20_contract)], addresses)
                .await
                .unwrap();

        assert_eq!(asset_sums[0], Fp::from(556863));
        assert_eq!(asset_sums[1], Fp::from(556863));
    }
}
