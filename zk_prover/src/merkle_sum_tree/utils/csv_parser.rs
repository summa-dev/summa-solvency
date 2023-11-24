use crate::merkle_sum_tree::Entry;
use num_bigint::BigUint;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::path::Path;

#[derive(Debug, Deserialize)]
struct CsvEntry {
    username: String,
    balances: String,
}

/// Parses a CSV file stored at path into a vector of Entries
pub fn parse_csv_to_entries<P: AsRef<Path>, const N_ASSETS: usize, const N_BYTES: usize>(
    path: P,
) -> Result<Vec<Entry<N_ASSETS>>, Box<dyn Error>> {
    let mut entries = Vec::new();
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new()
        .delimiter(b';') // The fields are separated by a semicolon
        .from_reader(file);

    let mut balances_acc: Vec<BigUint> = vec![BigUint::from(0_usize); N_ASSETS];

    for result in rdr.deserialize() {
        let record: CsvEntry = result?;

        // Split the balances string into separate balance strings
        let balance_strs: Vec<&str> = record.balances.split(',').collect();

        // Parse each balance string as a BigUint
        let balances_big_int: Vec<BigUint> = balance_strs
            .into_iter()
            .map(|balance_str| BigUint::parse_bytes(balance_str.as_bytes(), 10).unwrap())
            .collect();

        balances_acc = balances_acc
            .iter()
            .zip(balances_big_int.iter())
            .map(|(x, y)| x + y)
            .collect();

        let entry = Entry::new(record.username, balances_big_int.try_into().unwrap())?;
        entries.push(entry);
    }

    // Iterate through the balance accumulator and throw error if any balance is not in range 0, 2 ^ (8 * N_BYTES):
    for balance in balances_acc {
        if balance >= BigUint::from(2_usize).pow(8 * N_BYTES as u32) {
            return Err(
                "Accumulated balance is not in the expected range, proof generation will fail!"
                    .into(),
            );
        }
    }

    Ok(entries)
}
