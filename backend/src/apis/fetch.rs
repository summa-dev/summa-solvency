use base64::encode;
use ethers::solc::resolver::print;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use std::error::Error;

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

/// This function takes a list of asset contracts, a list of addresses and returns the aggregated balance of these address PER EACH asset
pub fn fetch_asset_sums(
    addresses: Vec<String>,
    asset_contract_addresses: Vec<String>,
) -> Result<Vec<u64>, Box<dyn Error>> {
    // create asset sums vector
    let mut asset_sums: Vec<u64> = Vec::new();

    // for each address in addresses vector call fetch_balances_per_addr and increment the asset_sums vector
    for address in addresses {
        let balances = fetch_balances_per_addr(address.clone(), asset_contract_addresses.clone())?;
        for (i, balance) in balances.iter().enumerate() {
            if asset_sums.len() <= i {
                asset_sums.push(*balance);
            } else {
                let sum = asset_sums[i] + balance;
                asset_sums[i] = sum;
            }
        }
    }

    Ok(asset_sums)
}

/// This function takes a list of token contracts, an address and returns the balances of that address for the queried contracts.
#[tokio::main]
async fn fetch_balances_per_addr(
    address: String,
    asset_contract_addresses: Vec<String>,
) -> Result<Vec<u64>, Box<dyn Error>> {
    // Create a header map
    let mut headers = HeaderMap::new();

    // Load .env file
    dotenv::dotenv().ok();

    // Access API key from the environment
    let api_key = std::env::var("COVALENT_API_KEY").unwrap();

    // Add `Content-Type` header
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    // Add `Authorization` header
    let auth_value = format!("Basic {}", encode(api_key));
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&auth_value)?);

    // Form URL
    let url = format!(
        "https://api.covalenthq.com/v1/eth-mainnet/address/{}/balances_v2/",
        address
    );

    // Send a GET request to the API
    let res = reqwest::Client::new()
        .get(&url)
        .headers(headers)
        .send()
        .await?
        .json::<Response>()
        .await?;

    // Get balances for the specific tokens
    let filtered_balances =
        filter_balances_by_token_contracts(asset_contract_addresses, &res).unwrap();

    Ok(filtered_balances)
}

/// This function filters out only the balances corresponding to an asset listed in asset_contract_addresses.
fn filter_balances_by_token_contracts(
    asset_contract_addresses: Vec<String>,
    response: &Response,
) -> Result<Vec<u64>, &'static str> {
    let mut balances = Vec::new();
    for contract in asset_contract_addresses {
        if let Some(item) = response.data.items.iter().find(|&item| {
            item.contract_address.to_ascii_lowercase() == contract.to_ascii_lowercase()
        }) {
            match item.balance.parse::<u64>() {
                Ok(num) => balances.push(num),
                Err(e) => println!("Failed to parse string: {}", e),
            }
        } else {
            balances.push(0 as u64);
        }
    }
    Ok(balances)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_balances_per_addr() {
        // this is an address with 0 usdc and 0.010910762665574143 ETH
        let address = "0xe4D9621321e77B499392801d08Ed68Ec5175f204".to_string();

        let usdc_contract = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48".to_string();
        let eth_contract = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();

        let balances =
            fetch_balances_per_addr(address, [usdc_contract, eth_contract].to_vec()).unwrap();

        assert_eq!(balances[0], 0); // usdc
        assert_eq!(balances[1], 10910762665574143); // wei
    }

    #[test]
    fn test_fetch_asset_sums() {
        let address_1 = "0xe4D9621321e77B499392801d08Ed68Ec5175f204".to_string(); // this is an address with 0 usdc and 0.010910762665574143 ETH
        let address_2 = "0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1".to_string(); // this is an address with 0.000001 USDC usdc and 1 wei

        let usdc_contract = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48".to_string();
        let eth_contract = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string();

        let balances = fetch_asset_sums(
            [address_1, address_2].to_vec(),
            [usdc_contract, eth_contract].to_vec(),
        )
        .unwrap();

        assert_eq!(balances[0], 1); // usdc
        assert_eq!(balances[1], 10910762665574144); // wei
    }
}
