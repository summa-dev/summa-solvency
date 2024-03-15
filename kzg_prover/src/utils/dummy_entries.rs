use num_bigint::BigUint;
use rand::{distributions::Alphanumeric, Rng};
use rayon::prelude::*;
use std::error::Error;

use crate::entry::Entry;

// This is for testing purposes with a large dataset instead of using a CSV file
pub fn generate_dummy_entries<const N_USERS: usize, const N_CURRENCIES: usize>(
) -> Result<Vec<Entry<N_CURRENCIES>>, Box<dyn Error>> {
    // Ensure N_CURRENCIES is greater than 0.
    if N_CURRENCIES == 0 {
        return Err("N_CURRENCIES must be greater than 0".into());
    }

    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];

    entries.par_iter_mut().for_each(|entry| {
        let mut rng = rand::thread_rng();

        let username: String = (0..10).map(|_| rng.sample(Alphanumeric) as char).collect();

        let balances: [BigUint; N_CURRENCIES] =
            std::array::from_fn(|_| BigUint::from(rng.gen_range(1000..90000) as u32));

        *entry = Entry::new(username, balances).expect("Failed to create entry");
    });

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_entries() {
        const N_USERS: usize = 1 << 17;
        const N_CURRENCIES: usize = 2;

        // Attempt to generate random entries
        let entries = generate_dummy_entries::<N_USERS, N_CURRENCIES>().unwrap();

        // Verify that entries are populated
        assert_eq!(entries.len(), N_USERS);
        for entry in entries {
            assert!(!entry.username().is_empty());
            assert_eq!(entry.balances().len(), N_CURRENCIES);
        }
    }

    #[test]
    fn test_asset_not_zero() {
        const N_USERS: usize = 1 << 17;
        const N_CURRENCIES: usize = 0;

        // `N_CURRENCIES` is zero, so this should fail
        assert!(generate_dummy_entries::<N_USERS, N_CURRENCIES>().is_err());
    }
}
