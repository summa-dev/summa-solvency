use crate::contracts::{generated::summa_contract::AddressOwnershipProof, signer::SummaSigner};
use std::{error::Error, result::Result};

use super::csv_parser::parse_signature_csv;

pub struct AddressOwnership<'a> {
    address_ownership_proofs: Vec<AddressOwnershipProof>,
    signer: &'a SummaSigner,
}

impl AddressOwnership<'_> {
    pub fn new<'a>(
        signer: &'a SummaSigner,
        signature_csv_path: &str,
    ) -> Result<AddressOwnership<'a>, Box<dyn Error>> {
        let address_ownership_proofs = parse_signature_csv(signature_csv_path)?;

        Ok(AddressOwnership {
            address_ownership_proofs,
            signer,
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
