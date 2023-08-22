use std::{sync::Arc, time::Duration};

use ethers::{
    prelude::{ContractFactory, SignerMiddleware},
    providers::{Http, Middleware, Provider},
    signers::{LocalWallet, Signer},
    types::{H160, U256},
    utils::{Anvil, AnvilInstance},
};
use tokio::time;

use crate::contracts::generated::mock_erc20::{MockERC20, MOCKERC20_ABI, MOCKERC20_BYTECODE};

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
    for addr in [cex_addr_1, cex_addr_2].to_vec() {
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

    return (anvil, cex_addr_1, cex_addr_2, client, mock_erc20);
}

mod test {
    use std::sync::Arc;

    use ethers::{
        abi::AbiEncode,
        providers::Middleware,
        types::{Address, Bytes, Filter, U256},
        utils::{keccak256, Anvil},
    };
    use snark_verifier_sdk::evm;

    use crate::contracts::{
        generated::{
            erc20_balance_retriever::ERC20BalanceRetriever,
            eth_balance_retriever::{self, ETHBalanceRetriever},
            evm_address_verifier::{self, EVMAddressVerifier},
            summa_contract::{
                ExchangeAddressesSubmittedFilter, OwnedAddress, OwnedAsset,
                ProofOfSolvencySubmittedFilter, Summa,
            },
            verifier::SolvencyVerifier,
        },
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
        let (anvil, cex_addr_1, cex_addr_2, client, mock_erc20) = initialize_anvil().await;

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

        let evm_address_verifier = EVMAddressVerifier::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let eth_balance_retriever = ETHBalanceRetriever::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let erc20_balance_retriever = ERC20BalanceRetriever::deploy(Arc::clone(&client), ())
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

        summa_contract
            .set_address_ownership_verifier(evm_address_verifier.address())
            .send()
            .await
            .unwrap();

        summa_contract
            .set_balance_retriever(eth_balance_retriever.address())
            .send()
            .await
            .unwrap();

        summa_contract
            .set_balance_retriever(erc20_balance_retriever.address())
            .send()
            .await
            .unwrap();

        let owned_addresses = vec![OwnedAddress {
          address_type: keccak256("EVM"),
          cex_address: cex_addr_1.encode().into(),
          ownership_proof:
            ("0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b").parse().unwrap()
        },OwnedAddress {
          address_type: keccak256("EVM"),
          cex_address: cex_addr_2.encode().into(),
          ownership_proof:
            ("0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c").parse().unwrap()
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
                addresses: vec![OwnedAddress {
                    address_type: keccak256("EVM"),
                    cex_address: cex_addr_1.encode().into(),
                    ownership_proof:
                        ("0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b").parse().unwrap()
                    },OwnedAddress {
                    address_type: keccak256("EVM"),
                    cex_address: cex_addr_2.encode().into(),
                    ownership_proof:
                        ("0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c").parse().unwrap()
                    },
                ],
            }
        );

        let owned_assets = vec![
            OwnedAsset {
                asset_type: keccak256("ETH"),
                addresses: vec![cex_addr_1.encode().into(), cex_addr_2.encode().into()],
                amount_to_prove: U256::from(556863),
                balance_retriever_args: Bytes::new(),
            },
            OwnedAsset {
                asset_type: keccak256("ERC20"),
                addresses: vec![cex_addr_2.encode().into()],
                amount_to_prove: U256::from(556863),
                balance_retriever_args: mock_erc20.address().encode().into(),
            },
        ];
        let result = summa_signer.submit_proof_of_solvency(
                    owned_assets,
                    serde_json::from_str::<U256>("\"0x2E021D9BF99C5BD7267488B6A7A5CF5F7D00222A41B6A9B971899C44089E0C5\"").unwrap(),
                    ( "0x1b9dffcf6d037dff3288d1de002fc5896c0cfd6b103f3d36167930bc40f5876301529271bd54bfbff665f8f67e1fa78a9b770fdb5d2fa82a91079a17c54f219213d55596340a726283fcbed3af1f3d82446abd4d281f900433abf8c93461e0b6120e0b3652d10a516d9683eb482757103c9132c143cd2e71e9eed7a57f3bfac302b2aff262b49857c6080775c5491c5f66524fc680844ddd661098ffbfa50ced0c16798a20cd89609848ccfa9255fc65b060cc5e9426f775e6ec1b165265dd821fdea20f9bf02781af932d7647d4b468cb67e76dc1d296eb120ac250a60bc21126c540cb68789f3d8c44e97486587c866c2912270b4516e902bc6cce0752854211c515e8cabcd10f65828c5fc5effca18097683feaca421d4079890a428a972414330624eee4c441dacfb6d3210305cd6d4100d53b562204283cf85a18c34a940513229beb20137d3d513140fcaae41dc69f8dd8ba0fb54141403e42be6421561a8095d0ad7e22844cc4fed035a069fa0327207ba33654fb3be3a2e80cfb5c34099d05e365c53e2a21fafc190981b4d81014383330b0b1b9a95226042be7787d24341e36d7eac6adbdeb3f90d90fcbec2ede52491329888201c9851248f528af1c1bab4b29a2220898fd013b2a2fea40a9c4b97caef707ae79a45acf6b3fdf891662ed4451de0f42400eb271355f0ba834783855aabce411cf4d47fe834e06ec05563f9fe170ec6ae1dee3682496985f9562560ea8fb95a9ef1230bd445315871b17882f050f440d5c521b727d9d8d3fec85ce65b975aa576314d34c311a5fe72e60ec351520837704ed307d7f477b7fe7d66f2a26c94e93db8997b0475bdb28247fd076a2deeddb8736f386dc2dc456418a0241ad53aa865782c300366c67682b20149982bc7572e43e0aeccedd0ca32bd6328fea410a07d80a03164ecc83082b614ba06782f70db6cfeaa82f9bff2b3651e34983eb2248d66c0efd07ad5daf11eaf7ada4a01c1411ce7aa951b770da9df8fe91bb9e65da7532bd92bb49929f2b5b9b6519de36ee9be866097fc53de89a99544d9792612a1901107b059fa903054f63b965e27e6eda3c8f9bb79c419f9b588785daa6523cbe48edd1aacbc4cd1210a77dff581a204e1c4b0e31396abe9ae8653bea3dc34c4870c7e48847df9e303c4eafb0e84b73e01e40b36a0b2c3cb43092067def02e52c329986a11d3a222825b9f25a7a80f91e5162f4b9cb1ffb4cacc974ca08de85905bb0921b6e0f4f07ce31ec7779f038e86424bb3aa2edbf0b08194b15d0d5d5d750ec6ae38f114a04d53b8820cdfef9f5a040ec8e5b97d4b7c933851f985264357a44037bd4433904e9d6bbe0791b4a4f664d8569d60b912630d291216261b8c4900b99590303680bc4d2feacf70b8ee6224786335346fdc1dcf5ee8a9edee15458e0fc443c37be246c10c913612d9e71fcb5050ca3fe748de3958f25d3baf5771c1ba7d4047bf527dbde51b0dffb9067fd4f81c77a03c3de127cf7564d6b4f0dcce6904fce9a7315a8074a89a921093d67d62090f6d08b58c7e9a2df1e6f207a7826ba2ade2f9e19a1657a895d397751bbac2fd452553a2df7fcb5822cc98d05fab41813bad4cf1af9fdfff8a1ae26ef204aa4c09af1074fde8f7702255a0dfc1463bc6c408eba0de7759154c4b92513efc9d4b342581eb1b8d491c7d80d39af9660a0c0ea015d1486edf45d6ee0c9f635e82b4814aae921d308ec86039d02e5dd6ddfbd352d8514931dcc1d5a6492c7eed79a1d3add532a17ddb4163fd5136676faeba0c51e2927556615ef01470ddd01e1e778ee09b103ef950d22c57912fd925d1054c7027b2339cf7529ca8c20e5adcd6b41322401b8a635606d1d03b46d062a1c5a56c7d324382c10d14cde82efcb21a22e7f3da8fae1cfe1b4d011c379b5fac9845511bf021efe0a1594dc0200283b7447b6da19e582c617c8e538af92f7151c21d2c6a40ff4a53401cbf9630f3c980fad67f9ea516960319f369ba586ea3992a10baf7502cc2043378f29ced2620ce8f741e023fe4bb3c8d46bb1477bdcd820d7e553822c714b607142a16e3b835b25a930c2f2e6120a5a143f659d367b4d84f0b8aa1126d8d9d9325b6c1f264aaa1c04fe34d2b1c1c488715d9e94868f56d04233c0300f6555c30d66fd0d07cd1ceed8ee3112503739b0512da71b021f0e0d0303a8f30a925da3a540c5ae1a2323be8070a4cb85f0c6ce8bbf87329c6c1f2bfa706c3d27850e8b495138097fdc204f97ca142da265e543b602c8ef9c84b677283014561668dc44a8137db8476a782b1e8c708ab3985119e6a0059b8c92b796718e6da90c167723952a9d6d3d22bde3e45421d942feb9343c423d80a5353e680852ed371bea33dcf58edc4a4cfe9bed6852be7a266d071de118d49b978e3405e651edfd18f118a7f845208f2898536b4903654286f7568b15b0f3fc9ac4672175b085f003d366d7516425e795a24ee39f7121da4938ca7d7b3b904979e24bc5830ae9532ae7fe07f7ffb7899c5ce01e21dacbcd1c4e62527bb5ec8f0744982a24c662c60d92da4be39e0f732854894d720b110dc91ecea6cef5ac3b542d360019d3e20701f493e5ab0e0db242bde3178f942089b7e37a87812b0b94435df6ee93dd029b2ed8550ae469fcdeb190e0767bc0627a093e4c51e3bcad39fee434519f0dd8e92f62bda41985e4e51df0a2625eee5ee7a1e77149ad689fa512a892ce2e77fa3822edf0f282e9c2f2eacbbabce2a0b97e79383ce52c9c5b246ab231c742ef3d8d23b504c261c34c656bb4cb663103c1385f9447373bb0899d253634f8c3c7581c0a4a343333130dcd05083489448fdbdf027cfd3cf4fd00a3fd14a6497026debe09816d743e8fd87e8ec09f466fe4d7665b62a57f4562fd40ca9d3151947a1989")
                   .parse().unwrap(),
                   U256::from(0)
        ).await;

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
                mst_root: "0x2E021D9BF99C5BD7267488B6A7A5CF5F7D00222A41B6A9B971899C44089E0C5"
                    .parse()
                    .unwrap(),
            }
        );

        drop(anvil);
    }
}
