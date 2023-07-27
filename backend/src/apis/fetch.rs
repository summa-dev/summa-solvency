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

use crate::contracts;
use contracts::generated::mock_erc20::MockERC20;

pub trait BalanceFromContract<M: Middleware> {
    fn get_balance_from_contract(&self, account: Address) -> ContractCall<M, U256>;
}

/// This function takes a list of token contracts, an address and returns the balances of that address for the queried contracts.
pub async fn fetch_asset_sums<'a, M: Middleware + 'a>(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    contracts: Vec<Box<dyn BalanceFromContract<M> + Send>>,
    asset_addresses: Vec<H160>,
) -> Result<Vec<U256>, Box<dyn Error>> {
    // For checking connectivity
    client.get_block_number().await?;

    let mut result: Vec<U256> = Vec::new();

    let mut get_balance_futures = Vec::new();
    for addr in asset_addresses.clone() {
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
    let mut sum_erc_balance = U256::zero();
    for contract in &contracts {
        for addr in asset_addresses.clone() {
            let erc_balance = contract
                .get_balance_from_contract(addr)
                .call()
                .await
                .unwrap();
            sum_erc_balance = sum_erc_balance + erc_balance;
        }
        result.push(sum_erc_balance)
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::contracts::tests::initialize_anvil;

    use ethers::utils::Anvil;

    #[tokio::test]
    async fn test_fetch_asset_sums() {
        // Necessary to implement `get_balance_from_contract` for the `contracts` parameter by following trait
        impl<M: Middleware> BalanceFromContract<M> for MockERC20<M> {
            fn get_balance_from_contract(&self, account: Address) -> ContractCall<M, U256> {
                self.balance_of(account)
            }
        }

        let anvil: ethers::utils::AnvilInstance = Anvil::new()
            .mnemonic("test test test test test test test test test test test junk")
            .spawn();

        let (cex_addr_1, cex_addr_2, client, mock_erc20) = initialize_anvil(&anvil).await;

        // send RPC requests with `anvil_setBalance` method via provider to adjust balance of `cex_addr_1` and `cex_addr_2`
        for addr in [cex_addr_1, cex_addr_2].to_vec() {
            let _res = client
                .provider()
                .request::<(H160, U256), ()>("anvil_setBalance", (addr, U256::from(278431)))
                .await;
        }

        let asset_sums = fetch_asset_sums(
            client.clone(),
            vec![Box::new(mock_erc20)],
            [cex_addr_1, cex_addr_2].to_vec(),
        )
        .await
        .unwrap();

        assert_eq!(asset_sums[0], U256::from(556862));
        assert_eq!(asset_sums[1], U256::from(556863));
    }
}
