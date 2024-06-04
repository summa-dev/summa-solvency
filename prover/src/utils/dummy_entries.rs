use num_bigint::BigUint;
use rand::{distributions::Alphanumeric, Rng};
use rayon::prelude::*;
use std::error::Error;

use crate::entry::Entry;

// This is for testing purposes with a large dataset instead of using a CSV file
pub fn generate_dummy_entries<const N_USERS: usize>() -> Result<Vec<Entry>, Box<dyn Error>> {
    let mut entries: Vec<Entry> = vec![Entry::init_empty(); N_USERS];

    entries.par_iter_mut().for_each(|entry| {
        let mut rng = rand::thread_rng();

        let username: String = (0..10).map(|_| rng.sample(Alphanumeric) as char).collect();

        let balance = BigUint::from(rng.gen_range(1000..90000) as u32);

        *entry = Entry::new(username, balance).expect("Failed to create entry");
    });

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random_entries() {
        const N_USERS: usize = 1 << 17;

        // Attempt to generate random entries
        let entries = generate_dummy_entries::<N_USERS>().unwrap();

        // Verify that entries are populated
        assert_eq!(entries.len(), N_USERS);
        for entry in entries {
            assert!(!entry.username().is_empty());
        }
    }
}
