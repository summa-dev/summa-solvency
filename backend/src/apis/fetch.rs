use futures::future::try_join_all;
use std::{error::Error, sync::Arc};

use ethers::{
    abi::Address,
    contract::builders::ContractCall,
    prelude::SignerMiddleware,
    providers::{Http, Middleware, Provider},
    signers::LocalWallet,
    types::{H160, U256},
};

pub trait TokenBalance<M: Middleware> {
    fn get_token_balance(&self, address: Address) -> ContractCall<M, U256>;
}

/// This function takes a list of token contracts, addresses and returns the balances of that address for the queried contracts.
/// The first balance returned is the Ether (ETH) balance, followed by the balances of other specified token contracts.
///
pub async fn fetch_asset_sums<'a, M: Middleware + 'a>(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    token_contracts: Vec<Box<dyn TokenBalance<M> + Send>>,
    exchange_addresses: Vec<H160>,
) -> Result<Vec<U256>, Box<dyn Error>> {
    let mut result: Vec<U256> = Vec::new();

    let mut get_balance_futures = Vec::new();
    for addr in exchange_addresses.clone() {
        get_balance_futures.push(client.get_balance(addr, None));
    }
    let get_balances = try_join_all(get_balance_futures).await?;
    let sum_eth_balance = get_balances
        .into_iter()
        .reduce(|acc, balance| acc + balance)
        .unwrap();
    result.push(sum_eth_balance);

    // Most in case, the number of contracts is less than the number of asset addresses
    // Iterating over contracts first is more efficient
    let mut sum_token_balance = U256::zero();
    for contract in &token_contracts {
        for addr in exchange_addresses.clone() {
            let token_balance = contract.get_token_balance(addr).call().await.unwrap();
            sum_token_balance = sum_token_balance + token_balance;
        }
        result.push(sum_token_balance)
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::contracts::generated::mock_erc20::MockERC20;
    use crate::contracts::tests::initialize_anvil;

    #[tokio::test]
    async fn test_fetch_asset_sums() {
        // Necessary to implement `get_balance_from_contract` for the `contracts` parameter by following trait
        impl<M: Middleware> TokenBalance<M> for MockERC20<M> {
            fn get_token_balance(&self, address: Address) -> ContractCall<M, U256> {
                self.balance_of(address)
            }
        }

        let (anvil, cex_addr_1, cex_addr_2, client, mock_erc20) = initialize_anvil().await;

        let asset_sums = fetch_asset_sums(
            client.clone(),
            vec![Box::new(mock_erc20)],
            [cex_addr_1, cex_addr_2].to_vec(),
        )
        .await
        .unwrap();

        assert_eq!(asset_sums[0], U256::from(556864));
        assert_eq!(asset_sums[1], U256::from(556863));

        drop(anvil);
    }
}
