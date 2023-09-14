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

use summa_backend::apis::csv_parser::SignatureRecord;

async fn remote_signer(mut stream: TcpStream) {
    let mut buffer = [0; 85];
    let bytes_read = stream.read(&mut buffer).unwrap();

    // This is insecure way to create wallet instances
    // TODO: suggest better secure way to generate wallet instances
    let private_keys = &[
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0xde9be858da4a475276426320d5e9262ecfc3ba460bfac56360bfa6c4c28b4ee0",
    ];

    let signing_wallets: Vec<LocalWallet> = private_keys
        .iter()
        .map(|private_key| LocalWallet::from_str(private_key).unwrap())
        .collect();

    let request = String::from_utf8_lossy(&buffer[..]);
    if request.starts_with("POST /sign") {
        // Extract the message from the request body
        let message = request.split("\r\n\r\n").nth(1).unwrap_or("");

        let encoded_message = encode(&[Token::String(message.to_owned())]);
        let hashed_message = keccak256(encoded_message);

        let mut signatures: Vec<SignatureRecord> = Vec::new();

        // Iterating signing wallets and generate signatures to put `signatures` vector
        for wallet in signing_wallets {
            let signature = wallet.sign_message(hashed_message).await.unwrap();
            let record = SignatureRecord::new(
                "ETH".to_string(),
                to_checksum(&wallet.address(), None), //
                format!("0x{}", signature.to_string()),
                message.to_string(),
            );
            signatures.push(record);
        }

        let json_response = to_string_pretty(&signatures).unwrap();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            json_response.len(),
            json_response
        );

        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    } else {
        let response = "HTTP/1.1 404 NOT FOUND\r\n\r\n";
        stream.write(response.as_bytes()).unwrap();
        stream.flush().unwrap();
    }
}

fn handle_client(stream: TcpStream) {
    let mut rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(remote_signer(stream));
}

pub fn start_server() {
    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    println!("Example Signer server started on 127.0.0.1:8080");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                std::thread::spawn(|| {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("Connection failed: {}", e);
            }
        }
    }
}
