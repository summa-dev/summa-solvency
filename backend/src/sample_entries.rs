use num_bigint::ToBigUint;
use summa_solvency::merkle_sum_tree::Entry;

pub fn get_sample_entries() -> Vec<Entry<2>> {
    let entries = vec![
        Entry::new(
            "dxGaEAii".to_string(),
            [11888.to_biguint().unwrap(), 41163.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "MBlfbBGI".to_string(),
            [67823.to_biguint().unwrap(), 18651.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "lAhWlEWZ".to_string(),
            [18651.to_biguint().unwrap(), 2087.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "nuZweYtO".to_string(),
            [22073.to_biguint().unwrap(), 55683.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "gbdSwiuY".to_string(),
            [34897.to_biguint().unwrap(), 83296.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "RZNneNuP".to_string(),
            [83296.to_biguint().unwrap(), 16881.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "YsscHXkp".to_string(),
            [31699.to_biguint().unwrap(), 35479.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "RkLzkDun".to_string(),
            [2087.to_biguint().unwrap(), 79731.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "HlQlnEYI".to_string(),
            [30605.to_biguint().unwrap(), 11888.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "RqkZOFYe".to_string(),
            [16881.to_biguint().unwrap(), 14874.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "NjCSRAfD".to_string(),
            [41163.to_biguint().unwrap(), 67823.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "pHniJMQY".to_string(),
            [14874.to_biguint().unwrap(), 22073.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "dOGIMzKR".to_string(),
            [10032.to_biguint().unwrap(), 10032.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "HfMDmNLp".to_string(),
            [55683.to_biguint().unwrap(), 34897.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "xPLKzCBl".to_string(),
            [79731.to_biguint().unwrap(), 30605.to_biguint().unwrap()],
        )
        .unwrap(),
        Entry::new(
            "AtwIxZHo".to_string(),
            [35479.to_biguint().unwrap(), 31699.to_biguint().unwrap()],
        )
        .unwrap(),
    ];

    entries
}
