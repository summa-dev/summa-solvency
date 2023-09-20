#![feature(generic_const_exprs)]
use std::{error::Error, fs::File};

use csv::WriterBuilder;

mod mock_signer;
use mock_signer::sign_message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // You can modify the message to gain better trust from users, or simply follow CEX requirements.
    // The message will be used to verify addresses and register them in the `ownershipProofByAddress` mapping on the Summa contract.
    let message = "Summa proof of solvency for CryptoExchange";
    let path = "src/apis/csv/signatures.csv";

    // Generate signatures for the given 'message' using the mock signer.
    // For this example, the 'mock_signer' file contains only the 'sign_message' function.
    // CEX should implement their own signer and use it here instead of 'sign_message'.
    let signatures = sign_message(message).await?;

    // Write the signatures to a CSV file to be used in the `verify_signatures` example.
    // It's envisioned that this CSV file will remain internal to CEX; only the Summa contract will publish its contents.
    let file = File::create(path)?;
    let mut wtr = WriterBuilder::new().delimiter(b';').from_writer(file);

    for signature in signatures {
        wtr.serialize(signature)?;
    }

    wtr.flush()?; // This will ensure all bytes are written
    println!("Successfully exported signatures to {}", path);

    Ok(())
}
