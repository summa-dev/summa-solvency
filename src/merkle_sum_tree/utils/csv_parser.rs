use crate::merkle_sum_tree::Entry;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CsvEntry {
    username: String,
    balance: u64,
}

pub fn parse_csv_to_entries<P: AsRef<Path>>(path: P) -> Result<Vec<Entry>, Box<dyn Error>> {
    let mut entries = Vec::new();
    let file = File::open(path)?;
    let mut rdr = csv::Reader::from_reader(file);

    for result in rdr.deserialize() {
        let record: CsvEntry = result?;
        let entry = Entry::new(record.username, record.balance)?;

        entries.push(entry);
    }

    Ok(entries)
}
