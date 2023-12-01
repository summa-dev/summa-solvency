use std::{error::Error, fs::File, path::Path};

use ethers::{abi::AbiEncode, types::Bytes};
use serde::{Deserialize, Serialize};

use crate::contracts::generated::summa_contract::AddressOwnershipProof;

#[derive(Debug, Deserialize, Serialize)]
pub struct SignatureRecord {
    chain: String,
    address: String,
    signature: String,
    message: String,
}

impl SignatureRecord {
    pub fn new(chain: String, address: String, signature: String, message: String) -> Self {
        Self {
            chain,
            address,
            signature,
            message,
        }
    }
}

pub fn parse_signature_csv<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<AddressOwnershipProof>, Box<dyn Error>> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().delimiter(b';').from_reader(file);

    let mut address_ownership_proofs = Vec::<AddressOwnershipProof>::new();

    for result in rdr.deserialize() {
        let record: SignatureRecord = result?;

        address_ownership_proofs.push(AddressOwnershipProof {
            cex_address: record.address.to_string(),
            chain: record.chain.to_string(),
            signature: record.signature.parse()?,
            message: Bytes::from(record.message.encode()),
        });
    }

    Ok(address_ownership_proofs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_to_signature() {
        let path = "../csv/signatures.csv";
        let address_ownership = parse_signature_csv(path).unwrap();

        let first_address_ownership = AddressOwnershipProof {
            chain: "ETH".to_string(),
            cex_address: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8".to_string(),
            signature:
              ("0x089b32327d332c295dc3b8873c205b72153211de6dc1c51235782b091cefb9d06d6df2661b86a7d441cd322f125b84901486b150e684221a7b7636eb8182af551b").parse().unwrap(),
              message:  "Summa proof of solvency for CryptoExchange".encode().into(),
          };

        assert_eq!(address_ownership[0], first_address_ownership);
    }
}
