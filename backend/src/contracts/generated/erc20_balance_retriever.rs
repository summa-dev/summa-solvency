pub use erc20_balance_retriever::*;
/// This module was auto-generated with ethers-rs Abigen.
/// More information at: <https://github.com/gakonst/ethers-rs>
#[allow(
    clippy::enum_variant_names,
    clippy::too_many_arguments,
    clippy::upper_case_acronyms,
    clippy::type_complexity,
    dead_code,
    non_camel_case_types,
)]
pub mod erc20_balance_retriever {
    #[rustfmt::skip]
    const __ABI: &str = "[{\"inputs\":[{\"internalType\":\"bytes\",\"name\":\"_address\",\"type\":\"bytes\",\"components\":[]},{\"internalType\":\"bytes\",\"name\":\"args\",\"type\":\"bytes\",\"components\":[]},{\"internalType\":\"uint256\",\"name\":\"timestamp\",\"type\":\"uint256\",\"components\":[]}],\"stateMutability\":\"view\",\"type\":\"function\",\"name\":\"getAddressBalance\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\",\"components\":[]}]},{\"inputs\":[],\"stateMutability\":\"pure\",\"type\":\"function\",\"name\":\"getAssetType\",\"outputs\":[{\"internalType\":\"bytes32\",\"name\":\"\",\"type\":\"bytes32\",\"components\":[]}]}]";
    ///The parsed JSON ABI of the contract.
    pub static ERC20BALANCERETRIEVER_ABI: ::ethers::contract::Lazy<
        ::ethers::core::abi::Abi,
    > = ::ethers::contract::Lazy::new(|| {
        ::ethers::core::utils::__serde_json::from_str(__ABI)
            .expect("ABI is always valid")
    });
    #[rustfmt::skip]
    const __BYTECODE: &[u8] = &[
        96,
        128,
        96,
        64,
        82,
        52,
        128,
        21,
        97,
        0,
        16,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        97,
        2,
        194,
        128,
        97,
        0,
        32,
        96,
        0,
        57,
        96,
        0,
        243,
        254,
        96,
        128,
        96,
        64,
        82,
        52,
        128,
        21,
        97,
        0,
        16,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        96,
        4,
        54,
        16,
        97,
        0,
        54,
        87,
        96,
        0,
        53,
        96,
        224,
        28,
        128,
        99,
        38,
        12,
        76,
        198,
        20,
        97,
        0,
        59,
        87,
        128,
        99,
        137,
        99,
        23,
        184,
        20,
        97,
        0,
        96,
        87,
        91,
        96,
        0,
        128,
        253,
        91,
        97,
        0,
        78,
        97,
        0,
        73,
        54,
        96,
        4,
        97,
        1,
        214,
        86,
        91,
        97,
        0,
        134,
        86,
        91,
        96,
        64,
        81,
        144,
        129,
        82,
        96,
        32,
        1,
        96,
        64,
        81,
        128,
        145,
        3,
        144,
        243,
        91,
        127,
        138,
        232,
        93,
        132,
        145,
        103,
        255,
        153,
        108,
        4,
        4,
        12,
        68,
        146,
        79,
        211,
        100,
        33,
        114,
        133,
        228,
        202,
        216,
        24,
        41,
        44,
        122,
        195,
        124,
        10,
        52,
        91,
        97,
        0,
        78,
        86,
        91,
        96,
        0,
        128,
        131,
        128,
        96,
        32,
        1,
        144,
        81,
        129,
        1,
        144,
        97,
        0,
        157,
        145,
        144,
        97,
        2,
        67,
        86,
        91,
        144,
        80,
        128,
        96,
        1,
        96,
        1,
        96,
        160,
        27,
        3,
        22,
        99,
        112,
        160,
        130,
        49,
        134,
        128,
        96,
        32,
        1,
        144,
        81,
        129,
        1,
        144,
        97,
        0,
        194,
        145,
        144,
        97,
        2,
        67,
        86,
        91,
        96,
        64,
        81,
        96,
        1,
        96,
        1,
        96,
        224,
        27,
        3,
        25,
        96,
        224,
        132,
        144,
        27,
        22,
        129,
        82,
        96,
        1,
        96,
        1,
        96,
        160,
        27,
        3,
        144,
        145,
        22,
        96,
        4,
        130,
        1,
        82,
        96,
        36,
        1,
        96,
        32,
        96,
        64,
        81,
        128,
        131,
        3,
        129,
        134,
        90,
        250,
        21,
        128,
        21,
        97,
        1,
        6,
        87,
        61,
        96,
        0,
        128,
        62,
        61,
        96,
        0,
        253,
        91,
        80,
        80,
        80,
        80,
        96,
        64,
        81,
        61,
        96,
        31,
        25,
        96,
        31,
        130,
        1,
        22,
        130,
        1,
        128,
        96,
        64,
        82,
        80,
        129,
        1,
        144,
        97,
        1,
        42,
        145,
        144,
        97,
        2,
        115,
        86,
        91,
        149,
        148,
        80,
        80,
        80,
        80,
        80,
        86,
        91,
        99,
        78,
        72,
        123,
        113,
        96,
        224,
        27,
        96,
        0,
        82,
        96,
        65,
        96,
        4,
        82,
        96,
        36,
        96,
        0,
        253,
        91,
        96,
        0,
        130,
        96,
        31,
        131,
        1,
        18,
        97,
        1,
        90,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        53,
        103,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        128,
        130,
        17,
        21,
        97,
        1,
        117,
        87,
        97,
        1,
        117,
        97,
        1,
        51,
        86,
        91,
        96,
        64,
        81,
        96,
        31,
        131,
        1,
        96,
        31,
        25,
        144,
        129,
        22,
        96,
        63,
        1,
        22,
        129,
        1,
        144,
        130,
        130,
        17,
        129,
        131,
        16,
        23,
        21,
        97,
        1,
        157,
        87,
        97,
        1,
        157,
        97,
        1,
        51,
        86,
        91,
        129,
        96,
        64,
        82,
        131,
        129,
        82,
        134,
        96,
        32,
        133,
        136,
        1,
        1,
        17,
        21,
        97,
        1,
        182,
        87,
        96,
        0,
        128,
        253,
        91,
        131,
        96,
        32,
        135,
        1,
        96,
        32,
        131,
        1,
        55,
        96,
        0,
        96,
        32,
        133,
        131,
        1,
        1,
        82,
        128,
        148,
        80,
        80,
        80,
        80,
        80,
        146,
        145,
        80,
        80,
        86,
        91,
        96,
        0,
        128,
        96,
        0,
        96,
        96,
        132,
        134,
        3,
        18,
        21,
        97,
        1,
        235,
        87,
        96,
        0,
        128,
        253,
        91,
        131,
        53,
        103,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        128,
        130,
        17,
        21,
        97,
        2,
        3,
        87,
        96,
        0,
        128,
        253,
        91,
        97,
        2,
        15,
        135,
        131,
        136,
        1,
        97,
        1,
        73,
        86,
        91,
        148,
        80,
        96,
        32,
        134,
        1,
        53,
        145,
        80,
        128,
        130,
        17,
        21,
        97,
        2,
        37,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        97,
        2,
        50,
        134,
        130,
        135,
        1,
        97,
        1,
        73,
        86,
        91,
        146,
        80,
        80,
        96,
        64,
        132,
        1,
        53,
        144,
        80,
        146,
        80,
        146,
        80,
        146,
        86,
        91,
        96,
        0,
        96,
        32,
        130,
        132,
        3,
        18,
        21,
        97,
        2,
        85,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        81,
        96,
        1,
        96,
        1,
        96,
        160,
        27,
        3,
        129,
        22,
        129,
        20,
        97,
        2,
        108,
        87,
        96,
        0,
        128,
        253,
        91,
        147,
        146,
        80,
        80,
        80,
        86,
        91,
        96,
        0,
        96,
        32,
        130,
        132,
        3,
        18,
        21,
        97,
        2,
        133,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        81,
        145,
        144,
        80,
        86,
        254,
        162,
        100,
        105,
        112,
        102,
        115,
        88,
        34,
        18,
        32,
        55,
        217,
        109,
        3,
        43,
        99,
        76,
        104,
        132,
        59,
        112,
        44,
        161,
        222,
        165,
        182,
        26,
        162,
        191,
        156,
        36,
        245,
        54,
        206,
        56,
        235,
        70,
        98,
        148,
        226,
        88,
        224,
        100,
        115,
        111,
        108,
        99,
        67,
        0,
        8,
        18,
        0,
        51,
    ];
    ///The bytecode of the contract.
    pub static ERC20BALANCERETRIEVER_BYTECODE: ::ethers::core::types::Bytes = ::ethers::core::types::Bytes::from_static(
        __BYTECODE,
    );
    #[rustfmt::skip]
    const __DEPLOYED_BYTECODE: &[u8] = &[
        96,
        128,
        96,
        64,
        82,
        52,
        128,
        21,
        97,
        0,
        16,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        96,
        4,
        54,
        16,
        97,
        0,
        54,
        87,
        96,
        0,
        53,
        96,
        224,
        28,
        128,
        99,
        38,
        12,
        76,
        198,
        20,
        97,
        0,
        59,
        87,
        128,
        99,
        137,
        99,
        23,
        184,
        20,
        97,
        0,
        96,
        87,
        91,
        96,
        0,
        128,
        253,
        91,
        97,
        0,
        78,
        97,
        0,
        73,
        54,
        96,
        4,
        97,
        1,
        214,
        86,
        91,
        97,
        0,
        134,
        86,
        91,
        96,
        64,
        81,
        144,
        129,
        82,
        96,
        32,
        1,
        96,
        64,
        81,
        128,
        145,
        3,
        144,
        243,
        91,
        127,
        138,
        232,
        93,
        132,
        145,
        103,
        255,
        153,
        108,
        4,
        4,
        12,
        68,
        146,
        79,
        211,
        100,
        33,
        114,
        133,
        228,
        202,
        216,
        24,
        41,
        44,
        122,
        195,
        124,
        10,
        52,
        91,
        97,
        0,
        78,
        86,
        91,
        96,
        0,
        128,
        131,
        128,
        96,
        32,
        1,
        144,
        81,
        129,
        1,
        144,
        97,
        0,
        157,
        145,
        144,
        97,
        2,
        67,
        86,
        91,
        144,
        80,
        128,
        96,
        1,
        96,
        1,
        96,
        160,
        27,
        3,
        22,
        99,
        112,
        160,
        130,
        49,
        134,
        128,
        96,
        32,
        1,
        144,
        81,
        129,
        1,
        144,
        97,
        0,
        194,
        145,
        144,
        97,
        2,
        67,
        86,
        91,
        96,
        64,
        81,
        96,
        1,
        96,
        1,
        96,
        224,
        27,
        3,
        25,
        96,
        224,
        132,
        144,
        27,
        22,
        129,
        82,
        96,
        1,
        96,
        1,
        96,
        160,
        27,
        3,
        144,
        145,
        22,
        96,
        4,
        130,
        1,
        82,
        96,
        36,
        1,
        96,
        32,
        96,
        64,
        81,
        128,
        131,
        3,
        129,
        134,
        90,
        250,
        21,
        128,
        21,
        97,
        1,
        6,
        87,
        61,
        96,
        0,
        128,
        62,
        61,
        96,
        0,
        253,
        91,
        80,
        80,
        80,
        80,
        96,
        64,
        81,
        61,
        96,
        31,
        25,
        96,
        31,
        130,
        1,
        22,
        130,
        1,
        128,
        96,
        64,
        82,
        80,
        129,
        1,
        144,
        97,
        1,
        42,
        145,
        144,
        97,
        2,
        115,
        86,
        91,
        149,
        148,
        80,
        80,
        80,
        80,
        80,
        86,
        91,
        99,
        78,
        72,
        123,
        113,
        96,
        224,
        27,
        96,
        0,
        82,
        96,
        65,
        96,
        4,
        82,
        96,
        36,
        96,
        0,
        253,
        91,
        96,
        0,
        130,
        96,
        31,
        131,
        1,
        18,
        97,
        1,
        90,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        53,
        103,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        128,
        130,
        17,
        21,
        97,
        1,
        117,
        87,
        97,
        1,
        117,
        97,
        1,
        51,
        86,
        91,
        96,
        64,
        81,
        96,
        31,
        131,
        1,
        96,
        31,
        25,
        144,
        129,
        22,
        96,
        63,
        1,
        22,
        129,
        1,
        144,
        130,
        130,
        17,
        129,
        131,
        16,
        23,
        21,
        97,
        1,
        157,
        87,
        97,
        1,
        157,
        97,
        1,
        51,
        86,
        91,
        129,
        96,
        64,
        82,
        131,
        129,
        82,
        134,
        96,
        32,
        133,
        136,
        1,
        1,
        17,
        21,
        97,
        1,
        182,
        87,
        96,
        0,
        128,
        253,
        91,
        131,
        96,
        32,
        135,
        1,
        96,
        32,
        131,
        1,
        55,
        96,
        0,
        96,
        32,
        133,
        131,
        1,
        1,
        82,
        128,
        148,
        80,
        80,
        80,
        80,
        80,
        146,
        145,
        80,
        80,
        86,
        91,
        96,
        0,
        128,
        96,
        0,
        96,
        96,
        132,
        134,
        3,
        18,
        21,
        97,
        1,
        235,
        87,
        96,
        0,
        128,
        253,
        91,
        131,
        53,
        103,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        255,
        128,
        130,
        17,
        21,
        97,
        2,
        3,
        87,
        96,
        0,
        128,
        253,
        91,
        97,
        2,
        15,
        135,
        131,
        136,
        1,
        97,
        1,
        73,
        86,
        91,
        148,
        80,
        96,
        32,
        134,
        1,
        53,
        145,
        80,
        128,
        130,
        17,
        21,
        97,
        2,
        37,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        97,
        2,
        50,
        134,
        130,
        135,
        1,
        97,
        1,
        73,
        86,
        91,
        146,
        80,
        80,
        96,
        64,
        132,
        1,
        53,
        144,
        80,
        146,
        80,
        146,
        80,
        146,
        86,
        91,
        96,
        0,
        96,
        32,
        130,
        132,
        3,
        18,
        21,
        97,
        2,
        85,
        87,
        96,
        0,
        128,
        253,
        91,
        129,
        81,
        96,
        1,
        96,
        1,
        96,
        160,
        27,
        3,
        129,
        22,
        129,
        20,
        97,
        2,
        108,
        87,
        96,
        0,
        128,
        253,
        91,
        147,
        146,
        80,
        80,
        80,
        86,
        91,
        96,
        0,
        96,
        32,
        130,
        132,
        3,
        18,
        21,
        97,
        2,
        133,
        87,
        96,
        0,
        128,
        253,
        91,
        80,
        81,
        145,
        144,
        80,
        86,
        254,
        162,
        100,
        105,
        112,
        102,
        115,
        88,
        34,
        18,
        32,
        55,
        217,
        109,
        3,
        43,
        99,
        76,
        104,
        132,
        59,
        112,
        44,
        161,
        222,
        165,
        182,
        26,
        162,
        191,
        156,
        36,
        245,
        54,
        206,
        56,
        235,
        70,
        98,
        148,
        226,
        88,
        224,
        100,
        115,
        111,
        108,
        99,
        67,
        0,
        8,
        18,
        0,
        51,
    ];
    ///The deployed bytecode of the contract.
    pub static ERC20BALANCERETRIEVER_DEPLOYED_BYTECODE: ::ethers::core::types::Bytes = ::ethers::core::types::Bytes::from_static(
        __DEPLOYED_BYTECODE,
    );
    pub struct ERC20BalanceRetriever<M>(::ethers::contract::Contract<M>);
    impl<M> ::core::clone::Clone for ERC20BalanceRetriever<M> {
        fn clone(&self) -> Self {
            Self(::core::clone::Clone::clone(&self.0))
        }
    }
    impl<M> ::core::ops::Deref for ERC20BalanceRetriever<M> {
        type Target = ::ethers::contract::Contract<M>;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl<M> ::core::ops::DerefMut for ERC20BalanceRetriever<M> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }
    impl<M> ::core::fmt::Debug for ERC20BalanceRetriever<M> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            f.debug_tuple(stringify!(ERC20BalanceRetriever))
                .field(&self.address())
                .finish()
        }
    }
    impl<M: ::ethers::providers::Middleware> ERC20BalanceRetriever<M> {
        /// Creates a new contract instance with the specified `ethers` client at
        /// `address`. The contract derefs to a `ethers::Contract` object.
        pub fn new<T: Into<::ethers::core::types::Address>>(
            address: T,
            client: ::std::sync::Arc<M>,
        ) -> Self {
            Self(
                ::ethers::contract::Contract::new(
                    address.into(),
                    ERC20BALANCERETRIEVER_ABI.clone(),
                    client,
                ),
            )
        }
        /// Constructs the general purpose `Deployer` instance based on the provided constructor arguments and sends it.
        /// Returns a new instance of a deployer that returns an instance of this contract after sending the transaction
        ///
        /// Notes:
        /// - If there are no constructor arguments, you should pass `()` as the argument.
        /// - The default poll duration is 7 seconds.
        /// - The default number of confirmations is 1 block.
        ///
        ///
        /// # Example
        ///
        /// Generate contract bindings with `abigen!` and deploy a new contract instance.
        ///
        /// *Note*: this requires a `bytecode` and `abi` object in the `greeter.json` artifact.
        ///
        /// ```ignore
        /// # async fn deploy<M: ethers::providers::Middleware>(client: ::std::sync::Arc<M>) {
        ///     abigen!(Greeter, "../greeter.json");
        ///
        ///    let greeter_contract = Greeter::deploy(client, "Hello world!".to_string()).unwrap().send().await.unwrap();
        ///    let msg = greeter_contract.greet().call().await.unwrap();
        /// # }
        /// ```
        pub fn deploy<T: ::ethers::core::abi::Tokenize>(
            client: ::std::sync::Arc<M>,
            constructor_args: T,
        ) -> ::core::result::Result<
            ::ethers::contract::builders::ContractDeployer<M, Self>,
            ::ethers::contract::ContractError<M>,
        > {
            let factory = ::ethers::contract::ContractFactory::new(
                ERC20BALANCERETRIEVER_ABI.clone(),
                ERC20BALANCERETRIEVER_BYTECODE.clone().into(),
                client,
            );
            let deployer = factory.deploy(constructor_args)?;
            let deployer = ::ethers::contract::ContractDeployer::new(deployer);
            Ok(deployer)
        }
        ///Calls the contract's `getAddressBalance` (0x260c4cc6) function
        pub fn get_address_balance(
            &self,
            address: ::ethers::core::types::Bytes,
            args: ::ethers::core::types::Bytes,
            timestamp: ::ethers::core::types::U256,
        ) -> ::ethers::contract::builders::ContractCall<M, ::ethers::core::types::U256> {
            self.0
                .method_hash([38, 12, 76, 198], (address, args, timestamp))
                .expect("method not found (this should never happen)")
        }
        ///Calls the contract's `getAssetType` (0x896317b8) function
        pub fn get_asset_type(
            &self,
        ) -> ::ethers::contract::builders::ContractCall<M, [u8; 32]> {
            self.0
                .method_hash([137, 99, 23, 184], ())
                .expect("method not found (this should never happen)")
        }
    }
    impl<M: ::ethers::providers::Middleware> From<::ethers::contract::Contract<M>>
    for ERC20BalanceRetriever<M> {
        fn from(contract: ::ethers::contract::Contract<M>) -> Self {
            Self::new(contract.address(), contract.client())
        }
    }
    ///Container type for all input parameters for the `getAddressBalance` function with signature `getAddressBalance(bytes,bytes,uint256)` and selector `0x260c4cc6`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(
        name = "getAddressBalance",
        abi = "getAddressBalance(bytes,bytes,uint256)"
    )]
    pub struct GetAddressBalanceCall {
        pub address: ::ethers::core::types::Bytes,
        pub args: ::ethers::core::types::Bytes,
        pub timestamp: ::ethers::core::types::U256,
    }
    ///Container type for all input parameters for the `getAssetType` function with signature `getAssetType()` and selector `0x896317b8`
    #[derive(
        Clone,
        ::ethers::contract::EthCall,
        ::ethers::contract::EthDisplay,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    #[ethcall(name = "getAssetType", abi = "getAssetType()")]
    pub struct GetAssetTypeCall;
    ///Container type for all of the contract's call
    #[derive(Clone, ::ethers::contract::EthAbiType, Debug, PartialEq, Eq, Hash)]
    pub enum ERC20BalanceRetrieverCalls {
        GetAddressBalance(GetAddressBalanceCall),
        GetAssetType(GetAssetTypeCall),
    }
    impl ::ethers::core::abi::AbiDecode for ERC20BalanceRetrieverCalls {
        fn decode(
            data: impl AsRef<[u8]>,
        ) -> ::core::result::Result<Self, ::ethers::core::abi::AbiError> {
            let data = data.as_ref();
            if let Ok(decoded)
                = <GetAddressBalanceCall as ::ethers::core::abi::AbiDecode>::decode(
                    data,
                ) {
                return Ok(Self::GetAddressBalance(decoded));
            }
            if let Ok(decoded)
                = <GetAssetTypeCall as ::ethers::core::abi::AbiDecode>::decode(data) {
                return Ok(Self::GetAssetType(decoded));
            }
            Err(::ethers::core::abi::Error::InvalidData.into())
        }
    }
    impl ::ethers::core::abi::AbiEncode for ERC20BalanceRetrieverCalls {
        fn encode(self) -> Vec<u8> {
            match self {
                Self::GetAddressBalance(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
                Self::GetAssetType(element) => {
                    ::ethers::core::abi::AbiEncode::encode(element)
                }
            }
        }
    }
    impl ::core::fmt::Display for ERC20BalanceRetrieverCalls {
        fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
            match self {
                Self::GetAddressBalance(element) => ::core::fmt::Display::fmt(element, f),
                Self::GetAssetType(element) => ::core::fmt::Display::fmt(element, f),
            }
        }
    }
    impl ::core::convert::From<GetAddressBalanceCall> for ERC20BalanceRetrieverCalls {
        fn from(value: GetAddressBalanceCall) -> Self {
            Self::GetAddressBalance(value)
        }
    }
    impl ::core::convert::From<GetAssetTypeCall> for ERC20BalanceRetrieverCalls {
        fn from(value: GetAssetTypeCall) -> Self {
            Self::GetAssetType(value)
        }
    }
    ///Container type for all return fields from the `getAddressBalance` function with signature `getAddressBalance(bytes,bytes,uint256)` and selector `0x260c4cc6`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetAddressBalanceReturn(pub ::ethers::core::types::U256);
    ///Container type for all return fields from the `getAssetType` function with signature `getAssetType()` and selector `0x896317b8`
    #[derive(
        Clone,
        ::ethers::contract::EthAbiType,
        ::ethers::contract::EthAbiCodec,
        Default,
        Debug,
        PartialEq,
        Eq,
        Hash
    )]
    pub struct GetAssetTypeReturn(pub [u8; 32]);
}
