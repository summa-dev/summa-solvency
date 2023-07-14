use std::error::Error;
use std::fs::File;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Record {
    address: String,
    signature: String,
}

pub fn parse_signature_csv<P: AsRef<Path>>(
    path: P,
) -> Result<(Vec<String>, Vec<String>), Box<dyn Error>> {
    let file = File::open(path)?;
    let mut rdr = csv::ReaderBuilder::new().delimiter(b';').from_reader(file);

    let mut signatures = Vec::<String>::new();
    let mut addresses = Vec::<String>::new();

    for result in rdr.deserialize() {
        let record: Record = result?;

        signatures.push(record.signature);
        addresses.push(record.address);
    }

    Ok((addresses, signatures))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_to_assets() {
        // these signatures are from contracts/test/Summa.ts
        let path = "src/apis/csv/signatures.csv";
        let (addresses, signatures) = parse_signature_csv(path).unwrap();

        assert_eq!(addresses[0], "0x70997970C51812dc3A010C7d01b50e0d17dc79C8");

        assert_eq!(
            signatures[0],
            "0xb17a9e25265d3b88de7bfad81e7accad6e3d5612308ff83cc0fef76a34152b0444309e8fc3dea5139e49b6fc83a8553071a7af3d0cfd3fb8c1aea2a4c171729c1c"
        );
    }
}
