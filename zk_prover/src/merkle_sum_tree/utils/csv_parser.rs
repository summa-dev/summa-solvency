use crate::merkle_sum_tree::{Cryptocurrency, Entry};
use num_bigint::BigUint;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::path::Path;

pub fn parse_csv_to_entries<P: AsRef<Path>, const N_CURRENCIES: usize, const N_BYTES: usize>(
    path: P,
) -> Result<(Vec<Cryptocurrency>, Vec<Entry<N_CURRENCIES>>), Box<dyn Error>> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().from_reader(file);

    let headers = rdr.headers()?.clone();
    let mut cryptocurrencies: Vec<Cryptocurrency> = Vec::with_capacity(N_CURRENCIES);

    // Extracting cryptocurrency names from column names
    for header in headers.iter().skip(1) {
        // Skipping 'username' column
        let parts: Vec<&str> = header.split('_').collect();
        if parts.len() == 3 && parts[0] == "balance" {
            cryptocurrencies.push(Cryptocurrency {
                name: parts[1].to_owned(),
                chain: parts[2].to_owned(),
            });
        } else {
            // Throw an error if the header is malformed
            return Err(format!("Invalid header: {}", header).into());
        }
    }

    let mut entries = Vec::new();
    let mut balances_acc: Vec<BigUint> = vec![BigUint::from(0_usize); N_CURRENCIES];

    for result in rdr.deserialize() {
        let record: HashMap<String, String> = result?;
        let username = record.get("username").ok_or("Username not found")?.clone();

        let mut balances_big_int = Vec::new();
        for cryptocurrency in &cryptocurrencies {
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
        entries.push(entry);
    }

    Ok((cryptocurrencies, entries))
}
