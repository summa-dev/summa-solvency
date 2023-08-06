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
            .set_asset_address_verifier(evm_address_verifier.address())
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
                    ( "0x095ccd79cf0fef9757faed74485f7ded9dce7a67490773630adce50112f1e13907f894b25e6ad9bfd5e88c4fbd01327976e70c8fb83016c4d2f21930f72278e2240e9e1d49eca19e6ae06e8f500442e69354c6855299ab806984971c07e935ed1aa8d7c3d3ec19f7a65df38ec899aa085e9d917b51781e2c89a57e4d033306be04c1ec6a7265dd96431fd06f59a7c10cdd1b2c17bb8a259ea1f0aa473990a7fd2633b8fa4d3395806dd22cb52edc43f313f6bafc368c151eb2110e20bab9f23f0c9d2d2aac1c6035695f8087fc70a5bb7440bc9dc9073f74b155756b61e9734d05260ef5fa80036420528a209e0c767e1726f8e64ebcfb5ee9a59d12edb50cfb042e43a2bda4bfdc02fad894ea18981ddc58c80af745f67b5ff97ef04f9b37c90b9eaedb194eda4d7abc8c49097304d2a8515f18620b9ff59bbc56e0dcbe377c1308f11d72d983e263fc440811d6e9f193b0a0fa264f38e67f4f431eceb8470920b263648501bd10d7ee87b1ac413ff080ceb691f53e95791e2a1e39deb1b1e72d2968566eebef50f4f2e79a91221eed08f4ac57f07cdfb3780001f73f5ea89f0066094b22cc19559c81b898193816359039435a69f34b9245b6db8c8f76e1aa075939e23db318371e7ee4f4ea41b548551457cb4131280794621ca72ba2cef007cffcf5ceb934bc9a69f2c80c0625b667842428081b74920e603957e172806f29dc85bd03199aad1988eba070e2bfc8a0a37f9984701d8857a84a65a64dbfa61ba6b830fa5047ad4be4bc6b3357481b8d83d677e03f27db83a147aa49218c1401533188c87da56d4b7871964fad13103bd5125e33ee3ac41d241dff20b4be5d0304a46b3f973064c76b9999207f0606b0dbf417fb8362e7f29773713764326e27d44618a59c7b2b741f2f9e5a225fd63482113795b81f3476224e4be55e89280cee3e773320d85b175670273a14c8e9b4821bf2069ef5254ebba4fe2ed7b744020fdef85cebaa478f34eddc114701de9d9f4c6318dd3e55349bc92f837bf01a0afaa3e07561e8a281898f69981a1505370aeb063a61a29cb713debbe4ca6cac2cf40034fc6faeeba1f31b78730521ec6b6de6e2d0ae2f4a0781b130680120131bbf8bffe56f5baa7556a0b846b2a827e8eb55ac207a528810a975281329cb7a04c5d064170e42cdf6c9d9291edc8c3373f9f73fc50f7ab8dec245bc155b27f7174f87f87670016ab8763f1121f05745c7d6f70114e81db2eb822a94f28ff29318de1f4fc21f8d3502fb0806ace655edcb2e68c57f841f186c834e306ca07f9c04d33d11ffe15f71eff3076d0ef01c6d434dc2fe13ae3d4536fff415613f5b5f13c5bcc11c5569651b58f300abcc1e4e8692f36adc21149d5989a494e1544ba6111b57c7d0dd823ab53191e7aded3e96e11a88546419d409a164708b0777a2ca2bef4a705d7e2048efdd9c5978e6fc3a23302547a082a3d0893d3500b8b6c1ac1ac376ec9ebe367b3f852c6eac7aa70b396985826e83e9cadb6e8bd9c889997907ca30a75797e24fd52db5ae01fee5bb60ad0a26e39f73bee7c319703e7a45c403fe6104fa01c8ee86bc5cd4d6ac229ec9d0a7151b10dc91309302e4113870841c786a41a9090004afaa14ef347429a29097f837ed9fa88cd8a0cfa158e2766c2926033bf5649846a3503a4f6cfe081e5f2a20df844428bef230df79ec079c8525304f246b6cb90e3616ca07a8b0e11ad5f8de084aa125a498890cc7a8ca3d530f2c1df65a6e163c4373efa7766b7cf76b87270c8493d6d54abcde7b1c15507008370cc980d7ad3828e204cd7ae65db8538c6f742d8d0f0de08450617dfe4b3a05fbd7c73836de16e166caf0a0996e42793c6ddf0945014b310e4ad9ee64a22a2a2f5df921226f31d81322e8cf26c6da09b1dffdb42942b3c24c717dfd09a0831e1d7ffd20f43a21f07051449bef2d7e7fa662233fe493191ae6960e70ed7b9027eaafe9e42c49d8bf01988eb6cbb5352248ecae0a7fd31f9784522738675b8b219d95479c69e4e4061cc059c6dc935a678799c05e25c6f3ff445758399d80ea30388310ae65091c556d902ccfe2c55dc0d36b5c650c9ff907a51c695fe04ced186033d72daa6a5e90b651a7c4439d8376c82d0b4e5a5bd55c4075c9cbeabbfc1831c82d27556c6a21805e37ee343af28d5b155dd4df511a7cfd61a23c3e883729e8faf874e65e49ca84d76af5a0f8c36229212fe5ce6c69b4f268095cb4e1da01e8ed9374da2a7caf40b42ae0aa8bddc477911bd6aeb3376620a9d177779f420577660b7f457c168b6d7c953649545b2bbb8f8f4f2a089f1add2dba02f745672ca2e8b6936aded6139df497ddf2c9580a0f6e4a215332b209c372b87bc02df4207906f52996194c8b90203c249c8e94120fd24c514d0534d6adb3b1432b9b9b0fe71c1e4e41d4fd7f4f38f8092da15093d64791cfa1989efb096b3bbcd6a28b08468788cb1496329e5a771e9ba6589798bc355479dc82982e2b586182ee47121aad284cdf04ea85714ea3c2a6d4c4a229ec4efb37f819d4ff7dc7be4c37d5cf0cb3a85190d269f5ed86568959c77016cfde4b625168a9d423c00d5b3468c9402087ce7b8f1d60561cae28355278302a80cbf41f6f5cb825cdb86848f5c612490b4f6a46f6e1ce405b3f2a5bb47fc41093b5a71bed6edcc26ba4774d62ae2a3c243d1449d88a62ecc9ad3b9cd3c75769a799c39e614773c60301adbf068a28152d360fa6f5bc0c28e6bbab10bcc5e7489a42479b7fe818839c480c6111f0093d11361f1e64cd5ad836ed5447b04d723bff21d8c532a8c5171a6052e8f715416b10a7350ee05209d05c89a38647c472a9cc3340bc297bab55d412b55e903b1ab020b8fb2ddba3489e975afd45001ab45d1da25c74c2dc63ec4a4c71542c05aa7c0c03e33520ae22819ac1610c83146f1293f75e9a3d570d98e2b1a6a7ba4480ee299ee59065eb72fe388128bf5a435cb31ed75a2703426ee79eb3224538f7acb009642910ff7f8f851c4e15ec89dcca116cffb699be25d16326ce3bb9cf00f763062b0b5dab0673b3e1c97e32a3a292d18dd3df69e223369ec988a586c3d4ec2c1bc914b6dd72b8d50ac2c8ac5375016e0f8f0deb2213f9836cbe0bb76fd238ab22b3dd71c800b022cb90e4984ecf2149b6940850ceec181e65d2e6c1cfbe378f")
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
