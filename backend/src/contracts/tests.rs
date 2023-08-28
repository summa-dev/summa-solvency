use std::{sync::Arc, time::Duration};

use ethers::{
    prelude::{ContractFactory, SignerMiddleware},
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{H160, U256},
    utils::{Anvil, AnvilInstance},
};
use tokio::time;

use crate::contracts::mock::mock_erc20::{MockERC20, MOCKERC20_ABI, MOCKERC20_BYTECODE};

// Setup test conditions on the anvil instance
pub async fn initialize_anvil() -> (
    AnvilInstance,
    H160,
    H160,
    Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
    MockERC20<SignerMiddleware<Provider<Http>, LocalWallet>>,
) {
    let anvil: ethers::utils::AnvilInstance = Anvil::new()
        .mnemonic("test test test test test test test test test test test junk")
        .spawn();

    // Extracting two exchange addresses from the Anvil instance
    let cex_addr_1 = anvil.addresses()[1];
    let cex_addr_2 = anvil.addresses()[2];

    // Setup wallet from the first key in the Anvil and an HTTP provider with a 10ms interval from the Anvil endpoint
    let wallet: LocalWallet = anvil.keys()[0].clone().into();
    let provider = Provider::<Http>::try_from(anvil.endpoint())
        .unwrap()
        .interval(Duration::from_millis(10u64));

    // Creating a client by wrapping the provider with a signing middleware and the Anvil chainid
    let client = Arc::new(SignerMiddleware::new(
        provider,
        wallet.with_chain_id(anvil.chain_id()),
    ));

    // Creating a factory to deploy a mock ERC20 contract
    let factory = ContractFactory::new(
        MOCKERC20_ABI.to_owned(),
        MOCKERC20_BYTECODE.to_owned(),
        Arc::clone(&client),
    );

    // Send RPC requests with `anvil_setBalance` method via provider to set ETH balance of `cex_addr_1` and `cex_addr_2`
    // This is for meeting `proof_of_solvency` test conditions
    for addr in [cex_addr_1, cex_addr_2].iter().copied() {
        let _res = client
            .provider()
            .request::<(H160, U256), ()>("anvil_setBalance", (addr, U256::from(278432)))
            .await;
    }

    // Deploy Mock ERC20 contract
    let mock_erc20_deployment = factory.deploy(()).unwrap().send().await.unwrap();

    // Creating an interface for the deployed mock ERC20 contract
    let mock_erc20 = MockERC20::new(mock_erc20_deployment.address(), Arc::clone(&client));

    // Mint some token to `cex_addr_2`
    let mint_call = mock_erc20.mint(cex_addr_2, U256::from(556863));
    assert!(mint_call.send().await.is_ok());

    time::sleep(Duration::from_millis(500)).await;

    (anvil, cex_addr_1, cex_addr_2, client, mock_erc20)
}

mod test {
    use serde_json::from_str;
    use std::{fs::read_to_string, sync::Arc};

    use ethers::{
        abi::AbiEncode,
        providers::Middleware,
        types::{Address, Bytes, Filter, U256},
        utils::{keccak256, Anvil},
    };
    use snark_verifier_sdk::evm;
    use summa_solvency::circuits::types::ProofSolidityCallData;

    use crate::contracts::{
        generated::{
            summa_contract::{
                AddressOwnershipProof, Asset, ExchangeAddressesSubmittedFilter,
                ProofOfSolvencySubmittedFilter, Summa,
            },
            verifier::SolvencyVerifier,
        },
        mock::mock_erc20,
        signer::SummaSigner,
        tests::initialize_anvil,
    };

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

    #[tokio::test]
    async fn test_submit_proof_of_solvency() {
        let (anvil, cex_addr_1, cex_addr_2, client, _mock_erc20) = initialize_anvil().await;

        let verifer_contract = SolvencyVerifier::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let summa_contract = Summa::deploy(Arc::clone(&client), verifer_contract.address())
            .unwrap()
            .send()
            .await
            .unwrap();

        let summa_signer = SummaSigner::new(
            &vec![
                "0xdf57089febbacf7ba0bc227dafbffa9fc08a93fdc68e1e42411a14efcf23656e",
                "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
            ],
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            anvil.chain_id(),
            anvil.endpoint().as_str(),
            summa_contract.address(),
        );

        let owned_addresses = vec![AddressOwnershipProof {
          chain: "ETH".to_string(),
          cex_address: cex_addr_1.to_string(),
          signature:
            ("0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b").parse().unwrap(),
            message:  "Summa proof of solvency for CryptoExchange".encode().into(),
        },AddressOwnershipProof {
          chain: "ETH".to_string(),
          cex_address: cex_addr_2.to_string(),
          signature:
            ("0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c").parse().unwrap(),
            message:  "Summa proof of solvency for CryptoExchange".encode().into(),
        }];
        let result = summa_signer
            .submit_proof_of_address_ownership(owned_addresses)
            .await;

        assert_eq!(result.is_ok(), true);

        let logs = summa_contract
            .exchange_addresses_submitted_filter()
            .query()
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0],
            ExchangeAddressesSubmittedFilter {
                address_ownership_proofs: vec![AddressOwnershipProof {
          chain: "ETH".to_string(),
          cex_address: cex_addr_1.to_string(),
          signature:
            ("0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b").parse().unwrap(),
            message:  "Summa proof of solvency for CryptoExchange".encode().into(),
        },AddressOwnershipProof {
          chain: "ETH".to_string(),
          cex_address: cex_addr_2.to_string(),
          signature:
            ("0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c").parse().unwrap(),
            message:  "Summa proof of solvency for CryptoExchange".encode().into(),
        },
                ],
            }
        );

        let path = "../zk_prover/examples/proof_solidity_calldata.json";
        let json_data = read_to_string(path).expect("Unable to read the file");
        let calldata: ProofSolidityCallData = from_str(&json_data).unwrap();

        let result = summa_signer
            .submit_proof_of_solvency(
                calldata.public_inputs[0],
                vec![
                    Asset {
                        asset_name: "ETH".to_string(),
                        chain: "ETH".to_string(),
                        amount: U256::from(556863),
                    },
                    Asset {
                        asset_name: "USDT".to_string(),
                        chain: "ETH".to_string(),
                        amount: U256::from(556863),
                    },
                ],
                calldata.proof.parse().unwrap(),
                U256::from(0),
            )
            .await;

        assert_eq!(result.is_ok(), true);

        let logs = summa_contract
            .proof_of_solvency_submitted_filter()
            .query()
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0],
            ProofOfSolvencySubmittedFilter {
                timestamp: U256::from(0),
                mst_root: "0x2E021D9BF99C5BD7267488B6A7A5CF5F7D00222A41B6A9B971899C44089E0C5"
                    .parse()
                    .unwrap(),
                assets: vec![
                    Asset {
                        asset_name: "ETH".to_string(),
                        chain: "ETH".to_string(),
                        amount: U256::from(556863)
                    },
                    Asset {
                        asset_name: "USDT".to_string(),
                        chain: "ETH".to_string(),
                        amount: U256::from(556863)
                    }
                ],
            }
        );

        drop(anvil);
    }
}
