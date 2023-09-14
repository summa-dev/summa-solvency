use std::{
    error::Error,
    fs::File,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    str::FromStr,
    thread::{sleep, spawn},
};

use csv::WriterBuilder;
use ethers::{
    abi::{encode, Token},
    prelude::SignerMiddleware,
    signers::{LocalWallet, Signer, WalletError},
    types::Signature,
    utils::{keccak256, to_checksum},
};
use serde_json::{from_str, to_string_pretty};

mod remote_signer;
use remote_signer::start_server;
use summa_backend::apis::csv_parser::SignatureRecord;

// We provide simple request function for getting signatures from the signer server
fn send_request(message: &str) -> Result<String, std::io::Error> {
    let mut stream = TcpStream::connect("127.0.0.1:8080")?;

    let request = format!(
        "POST /sign HTTP/1.1\r\nContent-Length: {}\r\n\r\n{}",
        message.len(),
        message
    );

    stream.write_all(request.as_bytes())?;

    let mut response = String::new();
    stream.read_to_string(&mut response)?;

    Ok(response)
}

fn parse_response(response: &str) -> Result<Vec<SignatureRecord>, Box<dyn std::error::Error>> {
    // Split the response into HTTP headers and body
    let parts: Vec<&str> = response.split("\r\n\r\n").collect();

    if parts.len() != 2 {
        return Err("Invalid response format".into());
    }

    let json_str = parts[1];

    // Parse the JSON response into a vector of SignatureRecord
    let signatures: Vec<SignatureRecord> = serde_json::from_str(json_str)?;

    Ok(signatures)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Let's assume the CEX has multiple private keys for generating message signatures for AddressOwnershipProof
    // Start the server in a separate thread
    spawn(|| start_server());

    // Give the server a little time to start
    sleep(std::time::Duration::from_secs(1));

    // Given message to sign
    // Note that, the message length are fixed for the server.
    let message = "Summa proof of solvency for CryptoExchange";
    let path = "src/apis/csv/signatures.csv";

    // Request signatures with `message` to the signer server
    let response = send_request(message)?;
    let signatures = parse_response(&response)?;

    // Write the signatures to a CSV file
    let file = File::create(path)?;
    let mut wtr = WriterBuilder::new().delimiter(b';').from_writer(file);

    for signature in signatures {
        wtr.serialize(signature)?;
    }

    wtr.flush()?; // This will ensure all bytes are written

    Ok(())
}
