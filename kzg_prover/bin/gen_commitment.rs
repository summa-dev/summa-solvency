#![feature(generic_const_exprs)]

use halo2_proofs::{arithmetic::Field, halo2curves::bn256::Fr as Fp};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::{fs::File, io::Write};
use summa_solvency::{
    circuits::{
        univariate_grand_sum::UnivariateGrandSum,
        utils::{full_prover, full_verifier, generate_setup_artifacts, open_grand_sums},
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::{big_uint_to_fp, parse_csv_to_entries},
};

const K: u32 = 17;
const N_CURRENCIES: usize = 2;
const N_USERS: usize = 16;

#[derive(Serialize, Deserialize)]
struct CommitmentSolidityCallData {
    range_check_snark_proof: String,
    grand_sums_batch_proofs: String,
}

fn main() {
    // Initialize with entries
    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

    parse_csv_to_entries::<&str, N_CURRENCIES>("../csv/entry_16.csv", &mut entries, &mut cryptos)
        .unwrap();

    let univariate_grand_sum_circuit =
        UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init(entries.to_vec());

    let (params, pk, _) = generate_setup_artifacts(
        K,
        Some("../backend/ptau/hermez-raw-17"),
        &univariate_grand_sum_circuit,
    )
    .unwrap();

    // Create a proof
    // TODO: Inside `full_prover` ~ update describe about instance
    let instances = vec![Fp::one(); 1]; // This instance is necessary to verify proof on solidity verifier.
    let (zk_snark_proof, advice_polys, _omega) = full_prover(
        &params,
        &pk,
        univariate_grand_sum_circuit.clone(),
        &[instances.clone()],
    );

    assert!(full_verifier(
        &params,
        pk.get_vk(),
        &zk_snark_proof,
        &[instances]
    ));

    let balance_column_range = 1..N_CURRENCIES + 1;
    let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

    for entry in &entries {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total[i] += balance;
        }
    }

    let poly_length = 1 << u64::from(K);

    let grand_sums_batch_proof = open_grand_sums(
        &advice_polys.advice_polys,
        &advice_polys.advice_blinds,
        &params,
        balance_column_range,
        csv_total
            .iter()
            .map(|x| big_uint_to_fp(&(x)) * Fp::from(poly_length).invert().unwrap())
            .collect::<Vec<Fp>>()
            .as_slice(),
    );

    let commitment = CommitmentSolidityCallData {
        range_check_snark_proof: format!("0x{}", hex::encode(zk_snark_proof)),
        grand_sums_batch_proofs: format!("0x{}", hex::encode(grand_sums_batch_proof)),
    };

    // Serialize to a JSON string
    let serialized_data = to_string_pretty(&commitment).expect("Failed to serialize data");

    // Save the serialized data to a JSON file
    let mut file =
        File::create("./bin/commitment_solidity_calldata.json").expect("Unable to create file");
    file.write_all(serialized_data.as_bytes())
        .expect("Unable to write data to file");
}
