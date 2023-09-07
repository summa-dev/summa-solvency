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
