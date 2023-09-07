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
    use halo2_proofs::halo2curves::bn256::Fr as Fp;

    use crate::apis::{ownership::AddressOwnership, round::Round};
    use crate::contracts::{
        generated::{
            inclusion_verifier::InclusionVerifier,
            solvency_verifier::SolvencyVerifier,
            summa_contract::{
                AddressOwnershipProof, AddressOwnershipProofSubmittedFilter, Asset,
                SolvencyProofSubmittedFilter, Summa,
            },
        },
        mock::mock_erc20,
        signer::SummaSigner,
    };
    use crate::tests::initialize_anvil;

    #[tokio::test]
    async fn test_round_features() {
        let (anvil, cex_addr_1, cex_addr_2, client, _mock_erc20) = initialize_anvil().await;

        let solvency_verifer_contract = SolvencyVerifier::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let inclusion_verifer_contract = InclusionVerifier::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let summa_contract = Summa::deploy(
            Arc::clone(&client),
            (
                solvency_verifer_contract.address(),
                inclusion_verifer_contract.address(),
            ),
        )
        .unwrap()
        .send()
        .await
        .unwrap();

        // Dispatch proof of address ownership
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

        let mut address_ownership_client = AddressOwnership::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            anvil.chain_id(),
            anvil.endpoint().as_str(),
            summa_contract.address(),
        )
        .unwrap();

        let ownership_submitted_result = address_ownership_client
            .dispatch_proof_of_address_ownership(owned_addresses)
            .await;

        assert_eq!(ownership_submitted_result.is_ok(), true);

        let logs = summa_contract
            .address_ownership_proof_submitted_filter()
            .query()
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0],
            AddressOwnershipProofSubmittedFilter {
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

        // Initialize round
        let mut round = Round::<4, 2, 14>::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // anvil account [0]
            anvil.chain_id(),
            anvil.endpoint().as_str(),
            summa_contract.address(),
        )
        .unwrap();

        let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
        let params_path = "ptau/hermez-raw-11";

        // Build snapshot
        round.build_snapshot(entry_csv, params_path, 1);

        // Verify solvency proof
        let mut logs = summa_contract
            .solvency_proof_submitted_filter()
            .query()
            .await
            .unwrap();
        assert_eq!(logs.len(), 0);

        // Dispatch solvency proof
        let assets = [
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
        ];

        assert_eq!(round.dispatch_solvency_proof(assets).await.unwrap(), ());

        // After sending transaction of proof of solvency, logs should be updated
        logs = summa_contract
            .solvency_proof_submitted_filter()
            .query()
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);

        assert_eq!(logs.len(), 1);
        assert_eq!(
            logs[0],
            SolvencyProofSubmittedFilter {
                timestamp: U256::from(1),
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

        // Test inclusion proof
        let inclusion_proof = round.get_proof_of_inclusion(0).unwrap();
        let proof = Bytes::from(inclusion_proof.get_proof().clone());
        let public_input_vec = inclusion_proof.get_public_inputs();

        // Fixing endianness
        let mut leaf_hash = public_input_vec[0][0].to_bytes();
        let mut root_hash = public_input_vec[0][1].to_bytes();
        leaf_hash.reverse();
        root_hash.reverse();

        let public_inputs = vec![
            U256::from_big_endian(&leaf_hash),
            U256::from_big_endian(&root_hash),
        ];

        let onchain_mstroot = summa_contract.mst_roots(U256::from(1)).await.unwrap();

        // Verify inclusion proof with onchain function
        summa_contract
            .verify_inclusion_proof(proof, public_inputs, U256::from(1))
            .await;
    }
}
