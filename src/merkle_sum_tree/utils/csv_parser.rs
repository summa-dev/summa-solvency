use crate::merkle_sum_tree::Entry;
use num_bigint::BigInt;
use serde::Deserialize;
use std::error::Error;
use std::fs::File;
use std::path::Path;

macro_rules! csv_entry {
    ($($name:ident),+) => {
        #[derive(Debug, Deserialize)]
        struct CsvEntry {
            username: String,
            $($name: String,)+
        }
    };
}

csv_entry!(balance1, balance2);

pub fn parse_csv_to_entries<P: AsRef<Path>, const N_ASSETS: usize>(
    path: P,
) -> Result<Vec<Entry<N_ASSETS>>, Box<dyn Error>> {
    let mut entries = Vec::new();
    let file = File::open(path)?;
    let mut rdr = csv::Reader::from_reader(file);

    let mut balances_acc: Vec<BigInt> = vec![BigInt::from(0); N_ASSETS];

    for result in rdr.deserialize() {
        let record: CsvEntry = result?;

        // Transform balance1 and balance2 to BigInt
        let balance1_big_int = BigInt::parse_bytes(record.balance1.as_bytes(), 10).unwrap();
        let balance2_big_int = BigInt::parse_bytes(record.balance2.as_bytes(), 10).unwrap();

        let balances_big_int = vec![balance1_big_int, balance2_big_int];

        balances_acc = balances_acc
            .iter()
            .zip(balances_big_int.iter())
            .map(|(x, y)| x + y)
            .collect();

        let entry = Entry::new(record.username, balances_big_int.try_into().unwrap())?;
        entries.push(entry);
    }

    // modulus from bn256 curve impl => https://github.com/privacy-scaling-explorations/halo2curves/blob/main/src/bn256/fr.rs#L38
    const MODULUS_STR: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

    // Iterate through the balance accumulator and throw error if any balance is larger than the modulus:
    for balance in balances_acc {
        if balance > BigInt::parse_bytes(MODULUS_STR.as_bytes(), 16).unwrap() {
            return Err("Balance is larger than the modulus".into());
        }
    }

    Ok(entries)
}
