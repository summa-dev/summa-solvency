use ethers::{
    abi::{encode, Token},
    types::U256,
    utils::keccak256,
};

use summa_backend::{apis::address_ownership::AddressOwnership, tests::initialize_test_env};

// In this example, we will demonstrate how to submit ownership of address to the Summa contract.
#[tokio::main]
async fn main() {
    // We have already demonstrated how to generate a CSV file containing the asset ownership proofs, `AddressOwnershipProof`.
    // For more details on this, kindly refer to the "generate_signature" example.

    // Initialize test environment without `address_ownership` instance from `initialize_test_env` function.
    let (anvil, _, _, _, summa_contract, _) = initialize_test_env().await;

    // For the current demonstration, we'll use the same CSV file produced in `generate_signature` example.
    let signature_csv_path = "src/apis/csv/signatures.csv";
    let mut address_ownership_client = AddressOwnership::new(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
        anvil.chain_id(),
        anvil.endpoint().as_str(),
        summa_contract.address(),
        signature_csv_path,
    )
    .unwrap();

    // Get hashed addresses using the `keccak256` method.
    let address_hashes = address_ownership_client
        .get_ownership_proofs()
        .iter()
        .map(|x| keccak256(encode(&[Token::String(x.cex_address.clone())])))
        .collect::<Vec<[u8; 32]>>();

    // Dispatches the proof of address ownership.
    // In the client, the `dispatch_proof_of_address_ownership` function sends a transaction to the Summa contract
    address_ownership_client
        .dispatch_proof_of_address_ownership()
        .await
        .unwrap();

    // If the `addressHash` isn't found in the `addressOwnershipProofs` mapping of the Summa contract,
    // it will return 0; otherwise, it will return a non-zero value.
    //
    // You can find unregistered address with null bytes as follows:
    //
    // let unregistered = summa_contract
    //     .ownership_proof_by_address([0u8; 32])
    //     .call()
    //     .await
    //     .unwrap();
    //
    // assert_eq!(unregistered, 0);

    // Check if the addresses are registered on the Summa contract.
    for address_hash in address_hashes.iter() {
        let registered = summa_contract
            .ownership_proof_by_address(*address_hash)
            .call()
            .await
            .unwrap();

        assert_ne!(registered, U256::from(0));
    }
    println!("Ownership proofs are submitted successfully!")
}
