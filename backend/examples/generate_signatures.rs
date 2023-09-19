#![feature(generic_const_exprs)]
use std::{error::Error, fs::File};

use csv::WriterBuilder;

mod mock_signer;
use mock_signer::sign_message;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Given message to sign
    let message = "Summa proof of solvency for CryptoExchange";
    let path = "src/apis/csv/signatures.csv";

    // Request signatures with `message` to the signer server
    let signatures = sign_message(message).await?;

    // Write the signatures to a CSV file
    let file = File::create(path)?;
    let mut wtr = WriterBuilder::new().delimiter(b';').from_writer(file);

    for signature in signatures {
        wtr.serialize(signature)?;
    }

    wtr.flush()?; // This will ensure all bytes are written
    println!("Successfully exported signatures to {}", path);

    Ok(())
}
