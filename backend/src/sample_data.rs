use crate::contracts::generated::summa_contract::{AddressOwnershipProof, Asset};
use ethers::{abi::AbiEncode, types::U256};
use num_bigint::ToBigUint;
use summa_solvency::merkle_sum_tree::Entry;

pub fn get_sample_address_ownership_proofs() -> Vec<AddressOwnershipProof> {
    vec![
      AddressOwnershipProof {
          chain: "ETH".to_string(),
          cex_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
          signature: "0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b".parse().unwrap(),
          message: "Summa proof of solvency for CryptoExchange".encode().into()
      },
      AddressOwnershipProof {
          chain: "ETH".to_string(),
          cex_address: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC".to_string(),
          signature: "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c".parse().unwrap(),
          message: "Summa proof of solvency for CryptoExchange".encode().into()
        },
  ]
}

pub fn get_sample_assets() -> [Asset; 2] {
    [
        Asset {
            asset_name: "ETH".to_string(),
            chain: "ETH".to_string(),
            amount: U256::from_dec_str("556863").expect("Invalid decimal string for amount"),
        },
        Asset {
            asset_name: "USDT".to_string(),
            chain: "ETH".to_string(),
            amount: U256::from_dec_str("556863").expect("Invalid decimal string for amount"),
        },
    ]
}

pub fn get_sample_entries() -> Vec<Entry<2>> {
    let entries = vec![
        Entry::new(
            "dxGaEAii".to_string(),
            [11888.to_biguint().unwrap(), 41163.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "MBlfbBGI".to_string(),
            [67823.to_biguint().unwrap(), 18651.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "lAhWlEWZ".to_string(),
            [18651.to_biguint().unwrap(), 2087.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "nuZweYtO".to_string(),
            [22073.to_biguint().unwrap(), 55683.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "gbdSwiuY".to_string(),
            [34897.to_biguint().unwrap(), 83296.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "RZNneNuP".to_string(),
            [83296.to_biguint().unwrap(), 16881.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "YsscHXkp".to_string(),
            [31699.to_biguint().unwrap(), 35479.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "RkLzkDun".to_string(),
            [2087.to_biguint().unwrap(), 79731.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "HlQlnEYI".to_string(),
            [30605.to_biguint().unwrap(), 11888.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "RqkZOFYe".to_string(),
            [16881.to_biguint().unwrap(), 14874.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "NjCSRAfD".to_string(),
            [41163.to_biguint().unwrap(), 67823.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "pHniJMQY".to_string(),
            [14874.to_biguint().unwrap(), 22073.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "dOGIMzKR".to_string(),
            [10032.to_biguint().unwrap(), 10032.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "HfMDmNLp".to_string(),
            [55683.to_biguint().unwrap(), 34897.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "xPLKzCBl".to_string(),
            [79731.to_biguint().unwrap(), 30605.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "AtwIxZHo".to_string(),
            [35479.to_biguint().unwrap(), 31699.to_biguint().unwrap()],
        )
        .unwrap(),
    ];

    entries
}
