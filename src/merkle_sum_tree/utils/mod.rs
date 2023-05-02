mod build_tree;
mod create_middle_node;
mod create_proof;
mod csv_parser;
mod hash;
mod index_of;
mod proof_verification;

pub use build_tree::build_merkle_tree_from_entries;
pub use create_middle_node::create_middle_node;
pub use create_proof::create_proof;
pub use csv_parser::parse_csv_to_entries;
pub use hash::poseidon;
pub use index_of::index_of;
pub use proof_verification::verify_proof;

// Add the big_intify_username function
pub fn big_intify_username(username: &str) -> u64 {
    let utf8_bytes = username.as_bytes();
    let hex_string = hex::encode(utf8_bytes);
    u64::from_str_radix(&hex_string, 16).unwrap_or(0)
}
