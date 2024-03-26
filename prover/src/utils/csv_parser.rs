use num_bigint::BigUint;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::Path;

use crate::cryptocurrency::Cryptocurrency;
use crate::entry::Entry;

pub fn parse_csv_to_entries<P: AsRef<Path>, const N_CURRENCIES: usize>(
    path: P,
    entries: &mut [Entry<N_CURRENCIES>],
    cryptocurrencies: &mut [Cryptocurrency],
) -> Result<(), Box<dyn Error>> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().from_reader(file);

    let headers = rdr.headers()?.clone();

    // Extracting cryptocurrency names from column names
    for (i, header) in headers.iter().skip(1).enumerate() {
        if i >= cryptocurrencies.len() {
            println!(
                "Too many columns in the CSV file, expected {}, skipping the rest",
                cryptocurrencies.len()
            );
            break;
        }
        // Skipping 'username' column
        let parts: Vec<&str> = header.split('_').collect();
        if parts.len() == 3 && parts[0] == "balance" {
            cryptocurrencies[i] = Cryptocurrency {
                name: parts[1].to_owned(),
                chain: parts[2].to_owned(),
            };
        } else {
            // Throw an error if the header is malformed
            return Err(format!("Invalid header: {}", header).into());
        }
    }

    let mut balances_acc: Vec<BigUint> = vec![BigUint::from(0_usize); N_CURRENCIES];

    for (i, result) in rdr.deserialize().enumerate() {
        let record: HashMap<String, String> = result?;
        let username = record.get("username").ok_or("Username not found")?.clone();

        let mut balances_big_int = Vec::new();
        for cryptocurrency in &mut *cryptocurrencies {
            let balance_str = record
                .get(format!("balance_{}_{}", cryptocurrency.name, cryptocurrency.chain).as_str())
                .ok_or(format!(
                    "Balance for {} on {} not found",
                    cryptocurrency.name, cryptocurrency.chain
                ))?;
            let balance = BigUint::parse_bytes(balance_str.as_bytes(), 10).ok_or(format!(
                "Invalid balance for {} on {}",
                cryptocurrency.name, cryptocurrency.chain
            ))?;
            balances_big_int.push(balance);
        }

        balances_acc = balances_acc
            .iter()
            .zip(balances_big_int.iter())
            .map(|(x, y)| x + y)
            .collect();

        let entry = Entry::new(username, balances_big_int.try_into().unwrap())?;
        entries[i] = entry;
    }

    Ok(())
}
