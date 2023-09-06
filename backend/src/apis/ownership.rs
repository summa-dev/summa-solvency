use crate::contracts::{generated::summa_contract::AddressOwnershipProof, signer::SummaSigner};
use ethers::types::Address;
use std::{error::Error, result::Result};

pub struct AddressOwnership {
    address_ownership_proofs: Vec<AddressOwnershipProof>,
    signer: SummaSigner,
}

impl AddressOwnership {
    pub fn new(
        main_signer_key: &str,
        chain_id: u64,
        rpc_url: &str,
        address: Address,
    ) -> Result<AddressOwnership, Box<dyn Error>> {
        Ok(AddressOwnership {
            address_ownership_proofs: vec![],
            signer: SummaSigner::new(&[], main_signer_key, chain_id, rpc_url, address),
        })
    }

    // Make sure the input `addresses` in `address_ownership_proof` are not duplicated with addresses already registered on the contract.
    pub async fn dispatch_proof_of_address_ownership(
        &mut self,
        address_ownership_proof: Vec<AddressOwnershipProof>,
    ) -> Result<(), Box<dyn Error>> {
        self.signer
            .submit_proof_of_address_ownership(address_ownership_proof.clone())
            .await?;

        self.address_ownership_proofs
            .extend(address_ownership_proof);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::{generated::summa_contract::Summa, tests::initialize_anvil};
    use ethers::abi::AbiEncode;
    use std::{str::from_utf8, str::FromStr, sync::Arc};

    // This test actually duplicated in `backend/src/contracts/tests.rs`
    // TODO: refactor this test to avoid duplication
    #[tokio::test]
    async fn test_submit_address_ownership() {
        let (anvil, cex_addr_1, cex_addr_2, client, _mock_erc20) = initialize_anvil().await;

        // No needed to deploy verifier contracts(inclusion and solvency) in this test
        // use arbitrary addresses for Summa contract
        let summa_contract =
            Summa::deploy(Arc::clone(&client), (Address::random(), Address::random()))
                .unwrap()
                .send()
                .await
                .unwrap();

        let mut address_ownership_client = AddressOwnership::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
            anvil.chain_id(),
            anvil.endpoint().as_str(),
            summa_contract.address(),
        )
        .unwrap();

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

        let result = address_ownership_client
            .dispatch_proof_of_address_ownership(owned_addresses)
            .await;

        assert_eq!(result.is_ok(), true);
    }
}
