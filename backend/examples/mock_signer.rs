use std::{error::Error, str::FromStr};

use ethers::{
    abi::{encode, Token},
    signers::{LocalWallet, Signer},
    utils::{keccak256, to_checksum},
};

use summa_backend::apis::csv_parser::SignatureRecord;

// Separated this function from the `generate_signatures.rs` for clarity on the example.
pub async fn sign_message(message: &str) -> Result<Vec<SignatureRecord>, Box<dyn Error>> {
    // Using private keys directly is insecure.
    // Instead, consider leveraging hardware wallet support.
    // `ethers-rs` provides support for both Ledger and Trezor hardware wallets.
    //
    // For example, you could use the Ledger wallet as shown below:
    // let signing_wallets = (0..2).map(|index| Ledger::new(HDPath::LedgerLive(index), 1).await.unwrap()).collect();
    //
    // Refers to: https://docs.rs/ethers/latest/ethers/signers/index.html
    let private_keys = &[
        "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    ];

    let signing_wallets: Vec<LocalWallet> = private_keys
        .iter()
        .map(|private_key| LocalWallet::from_str(private_key).unwrap())
        .collect();

    let encoded_message = encode(&[Token::String(message.to_owned())]);
    let hashed_message = keccak256(encoded_message);

    let mut signatures: Vec<SignatureRecord> = Vec::new();

    // Iterating signing wallets and generate signature to put `signatures` vector
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

    Ok(signatures)
}
