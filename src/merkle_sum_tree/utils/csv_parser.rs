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

    for result in rdr.deserialize() {
        let record: CsvEntry = result?;
        let balance_big_int = BigInt::parse_bytes(record.balance.as_bytes(), 10).unwrap();
        let entry = Entry::new(record.username, balance_big_int)?;

        entries.push(entry);
    }

    Ok(entries)
}
