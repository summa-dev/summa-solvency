#![feature(generic_const_exprs)]

use serde_json::to_string_pretty;
use std::{fs::File, io::Write};
use summa_solvency::{
    circuits::types::CommitmentSolidityCallData,
    circuits::utils::field_element_to_solidity_calldata,
    merkle_sum_tree::{MerkleSumTree, Tree},
};

const N_CURRENCIES: usize = 2;
const N_BYTES: usize = 8;

fn main() {
    let merkle_sum_tree =
        MerkleSumTree::<N_CURRENCIES, N_BYTES>::from_csv("../csv/entry_16.csv").unwrap();

    let root = merkle_sum_tree.root();

    // The commitment to be published on-chain is made of (root_hash, root_balances)
    let root_hash_hex_string = field_element_to_solidity_calldata(root.hash);
    let root_balances_hex_strings: Vec<ethers::types::U256> = root
        .balances
        .iter()
        .map(|balance| field_element_to_solidity_calldata(*balance))
        .collect();

    let commitment = CommitmentSolidityCallData {
        root_hash: root_hash_hex_string,
        root_balances: root_balances_hex_strings,
    };

    // Serialize to a JSON string
    let serialized_data = to_string_pretty(&commitment).expect("Failed to serialize data");

    // Save the serialized data to a JSON file
    let mut file = File::create("./examples/commitment_solidity_calldata.json")
        .expect("Unable to create file");
    file.write_all(serialized_data.as_bytes())
        .expect("Unable to write data to file");
}
