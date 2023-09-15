use crate::contracts::{generated::summa_contract::AddressOwnershipProof, signer::SummaSigner};
use ethers::types::Address;
use std::{error::Error, result::Result};

use super::csv_parser::parse_signature_csv;

pub struct AddressOwnership {
    address_ownership_proofs: Vec<AddressOwnershipProof>,
    signer: SummaSigner,
}

impl AddressOwnership {
    pub fn new(
        signer_key: &str,
        chain_id: u64,
        rpc_url: &str,
        summa_sc_address: Address,
        signature_csv_path: &str,
    ) -> Result<AddressOwnership, Box<dyn Error>> {
        let address_ownership_proofs = parse_signature_csv(signature_csv_path)?;

        Ok(AddressOwnership {
            address_ownership_proofs,
            signer: SummaSigner::new(signer_key, chain_id, rpc_url, summa_sc_address),
        })
    }

    pub fn get_ownership_proofs(&self) -> &Vec<AddressOwnershipProof> {
        &self.address_ownership_proofs
    }

    // This function dispatches the proof of address ownership. Before calling this function,
    // ensure externally that the provided `addresses` in `address_ownership_proof` are not already registered
    // on the Summa contract.
    pub async fn dispatch_proof_of_address_ownership(&mut self) -> Result<(), Box<dyn Error>> {
        self.signer
            .submit_proof_of_address_ownership(self.address_ownership_proofs.clone())
            .await?;

        Ok(())
    }
}
