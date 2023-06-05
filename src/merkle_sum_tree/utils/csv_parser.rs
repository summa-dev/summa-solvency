use crate::merkle_sum_tree::Entry;
use num_bigint::BigInt;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CsvEntry {
    username: String,
    balance: String,
}

pub fn parse_csv_to_entries<P: AsRef<Path>>(path: P) -> Result<Vec<Entry>, Box<dyn Error>> {
    let mut entries = Vec::new();
    let file = File::open(path)?;
    let mut rdr = csv::Reader::from_reader(file);

    let mut balance_acc = BigInt::from(0);

    for result in rdr.deserialize() {
        let record: CsvEntry = result?;
        let balance_big_int = BigInt::parse_bytes(record.balance.as_bytes(), 10).unwrap();
        balance_acc += &balance_big_int;
        let entry = Entry::new(record.username, balance_big_int)?;
        entries.push(entry);
    }

    // For preventing overflow, we set the maximum value limit to 2^251 - 1
    const MAX_VALUE_STR: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    // throw error if balance is larger than the modulus
    if balance_acc >= BigInt::parse_bytes(MAX_VALUE_STR.as_bytes(), 16).unwrap() {
        return Err("Balance is larger than the maximum value limit".into());
    }

    Ok(entries)
}
