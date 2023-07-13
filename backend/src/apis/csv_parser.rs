use std::error::Error;
use std::fs::File;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CsvWallet {
    pubkey: String,
    signature: String,
}

pub fn parse_wallet_csv<P: AsRef<Path>>(
    path: P,
) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().delimiter(b';').from_reader(file);

    let mut signatures = Vec::<String>::new();
    let mut pubkey = Vec::<String>::new();

    for result in rdr.deserialize() {
        let record: CsvWallet = result?;

        signatures.push(record.signature);
        pubkey.push(record.pubkey);
    }

    Ok((pubkey, signatures))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_to_assets() {
        let path = "src/apis/csv/wallet_2.csv";
        let (assets, signatures) = parse_wallet_csv(path).unwrap();

        assert_eq!(assets[0], "0x627306090abaB3A6e1400e9345bC60c78a8BEf57");

        assert_eq!(
            signatures[0],
            "3045022100c12a7d54972f26d4f4766b8ad5d7a3d7cfe1b5ce3c1e1a9116a6a25db11d8d7a0220476fc1d66f673f52f9dd8c637f62f6e4e2a31dbca5f65fddbca9f3faff9f6d6b"
        );
    }
}
