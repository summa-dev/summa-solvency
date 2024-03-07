use num_bigint::BigUint;
use rand::{distributions::Alphanumeric, Rng};
use rayon::prelude::*;
use std::error::Error;

use crate::cryptocurrency::Cryptocurrency;
use crate::entry::Entry;

// This is for testing purposes with a large dataset instead of using a CSV file
pub fn generate_dummy_entries<const N_ASSETS: usize>(
    entries: &mut [Entry<N_ASSETS>],
    cryptocurrencies: &mut [Cryptocurrency],
) -> Result<(), Box<dyn Error>> {
    // Ensure N_ASSETS is greater than 0.
    if N_ASSETS == 0 {
        return Err("N_ASSETS must be greater than 0".into());
    }

    // Ensure the length of `cryptocurrencies` matches `N_ASSETS`.
    if cryptocurrencies.len() != N_ASSETS {
        return Err("cryptocurrencies length must be equal to N_ASSETS".into());
    }

    for (i, cryptocurrency) in cryptocurrencies.iter_mut().enumerate() {
        *cryptocurrency = Cryptocurrency {
            name: format!("ETH{i}"),
            chain: "ETH".to_string(),
        };
    }

    entries.par_iter_mut().for_each(|entry| {
        let mut rng = rand::thread_rng();

        let username: String = (0..10).map(|_| rng.sample(Alphanumeric) as char).collect();

        let balances: [BigUint; N_ASSETS] =
            std::array::from_fn(|_| BigUint::from(rng.gen_range(1000..90000) as u32));

        *entry = Entry::new(username, balances).expect("Failed to create entry");
    });

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptocurrency::Cryptocurrency;
    use crate::entry::Entry;

    #[test]
    fn test_generate_random_entries() {
        const N_USERS: usize = 1 << 17;
        const N_ASSETS: usize = 2;

        // Setup a buffer for entries and cryptocurrencies
        let mut entries = vec![Entry::<N_ASSETS>::init_empty(); N_USERS];
        let mut cryptocurrencies = vec![Cryptocurrency::init_empty(); N_ASSETS];

        // Attempt to generate random entries
        assert!(generate_dummy_entries::<N_ASSETS>(&mut entries, &mut cryptocurrencies).is_ok());

        // Verify that entries are populated
        assert_eq!(entries.len(), N_USERS);
        for entry in entries {
            assert!(!entry.username().is_empty());
            assert_eq!(entry.balances().len(), N_ASSETS);
        }
    }

    #[test]
    fn test_asset_not_zero() {
        const N_USERS: usize = 1 << 17;
        const N_ASSETS: usize = 0;

        // Setup a buffer for entries and cryptocurrencies
        let mut entries = vec![Entry::<N_ASSETS>::init_empty(); N_USERS];
        let mut cryptocurrencies = vec![Cryptocurrency::init_empty(); N_ASSETS];

        // `N_ASSETS` is zero, so this should fail
        assert!(generate_dummy_entries::<N_ASSETS>(&mut entries, &mut cryptocurrencies).is_err());
    }

    #[test]
    fn test_wrong_cryptocurrencies() {
        const N_USERS: usize = 1 << 17;
        const N_ASSETS: usize = 2;

        // Setup a buffer for entries and cryptocurrencies
        let mut entries = vec![Entry::<N_ASSETS>::init_empty(); N_USERS];
        let mut cryptocurrencies = vec![Cryptocurrency::init_empty(); N_ASSETS + 1];

        // `cryptocurrencies` length is not equal to `N_ASSETS`, so this should fail
        assert!(generate_dummy_entries::<N_ASSETS>(&mut entries, &mut cryptocurrencies).is_err());
    }
}
