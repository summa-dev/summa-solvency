#![feature(generic_const_exprs)]
use std::error::Error;

use halo2_proofs::halo2curves::bn256::{Fr as Fp, G1Affine};
use halo2_proofs::halo2curves::group::Curve;
use halo2_proofs::transcript::TranscriptRead;
use halo2_proofs::{
    arithmetic::Field, halo2curves::bn256::Bn256, poly::kzg::commitment::KZGCommitmentScheme,
};
use halo2_solidity_verifier::Keccak256Transcript;
use num_bigint::BigUint;

use summa_solvency::circuits::utils::generate_setup_artifacts;
use summa_solvency::{
    circuits::{
        univariate_grand_sum::{NoRangeCheckConfig, UnivariateGrandSum},
        utils::full_prover,
    },
    cryptocurrency::Cryptocurrency,
    entry::Entry,
    utils::{
        amortized_kzg::{commit_kzg, create_naive_kzg_proof, verify_kzg_proof},
        big_uint_to_fp, parse_csv_to_entries,
    },
};

const K: u32 = 9;
const N_CURRENCIES: usize = 2;
const N_USERS_TOTAL: usize = 64;
const N_USERS_CHUNK: usize = N_USERS_TOTAL / 2;

fn main() -> Result<(), Box<dyn Error>> {
    let path = "../csv/entry_64.csv";

    let mut entries: Vec<Entry<N_CURRENCIES>> = vec![Entry::init_empty(); N_USERS_TOTAL];
    let mut cryptos = vec![Cryptocurrency::init_empty(); N_CURRENCIES];

    parse_csv_to_entries::<&str, N_CURRENCIES>(path, &mut entries, &mut cryptos).unwrap();

    // Calculate total for all balance entries
    let mut csv_total: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];

    for entry in &entries {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total[i] += balance;
        }
    }

    // Split the user base into two equal chunks of N_USERS_TOTAL/2 each
    let entries_first_chunk = entries[0..N_USERS_CHUNK].to_vec();
    // Calculate the total for the first chunk
    let mut csv_total_1: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];
    for entry in &entries_first_chunk {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total_1[i] += balance;
        }
    }
    let entries_second_chunk = entries[N_USERS_CHUNK..].to_vec();
    // Calculate the total for the second chunk
    let mut csv_total_2: Vec<BigUint> = vec![BigUint::from(0u32); N_CURRENCIES];
    for entry in &entries_second_chunk {
        for (i, balance) in entry.balances().iter().enumerate() {
            csv_total_2[i] += balance;
        }
    }
    // Index of the advice polynomial to be used for the subsequent examples
    const BALANCES_INDEX: usize = 1;
    assert!(
        &csv_total_1[BALANCES_INDEX - 1] + &csv_total_2[BALANCES_INDEX - 1]
            == csv_total[BALANCES_INDEX - 1],
        "The sum of the chunks' total should be equal to the grand total"
    );

    type CONFIG = NoRangeCheckConfig<N_CURRENCIES, N_USERS_CHUNK>;

    let circuit_1 = UnivariateGrandSum::<N_USERS_CHUNK, N_CURRENCIES, CONFIG>::init_empty();
    // Generate the setup artifacts using an empty circuit
    let (params, pk, vk) = generate_setup_artifacts(K, None, &circuit_1).unwrap();

    // Instantiate the actual circuits for the first and second chunk
    let circuit_1 =
        UnivariateGrandSum::<N_USERS_CHUNK, N_CURRENCIES, CONFIG>::init(entries_first_chunk);
    let circuit_2 =
        UnivariateGrandSum::<N_USERS_CHUNK, N_CURRENCIES, CONFIG>::init(entries_second_chunk);

    // The zkSNARK proofs encode the balances of the first chunk and the second chunk
    // in the corresponding advice polynomials
    let (proof_1, advice_polys_1, _) = full_prover(&params, &pk, circuit_1.clone(), &[vec![]]);
    let (proof_2, advice_polys_2, _) = full_prover(&params, &pk, circuit_2.clone(), &[vec![]]);

    // Get the BALANCES_INDEX advice polynomial from each chunk
    let f_poly_1 = advice_polys_1.advice_polys.get(BALANCES_INDEX).unwrap();
    let f_poly_2 = advice_polys_2.advice_polys.get(BALANCES_INDEX).unwrap();

    // These advice polynomials can then be used to independently produce the user inclusion KZG proofs.
    // This allows to significantly speed up the inclusion proof by using smaller `N_USERS_CHUNK` size
    // and parallelizing the proof generation.

    // Take the KZG commitment of each chunk from the zkSNARK proof transcript
    let mut transcript_1 = Keccak256Transcript::new(proof_1.as_slice());
    let mut advice_commitments_1 = Vec::new();
    (0..N_CURRENCIES + 1).for_each(|_| {
        let point: G1Affine = transcript_1.read_point().unwrap();
        advice_commitments_1.push(point);
    });
    let kzg_commitment_1 = advice_commitments_1[BALANCES_INDEX];
    let mut transcript_2 = Keccak256Transcript::new(proof_2.as_slice());
    let mut advice_commitments_2 = Vec::new();
    (0..N_CURRENCIES + 1).for_each(|_| {
        let point: G1Affine = transcript_2.read_point().unwrap();
        advice_commitments_2.push(point);
    });
    let kzg_commitment_2 = advice_commitments_2[BALANCES_INDEX];
    assert!(
        kzg_commitment_1 != kzg_commitment_2,
        "Commitments should be different"
    );

    // The homomorphic property of KZG commitments allows us to sum the individual chunk commitments
    // to produce the KZG opening proof for the grand total
    let kzg_commitment_sum = kzg_commitment_1 + kzg_commitment_2;

    // First, add the polynomials together coefficient-wise
    let domain = vk.get_domain();
    let mut f_poly_total = domain.empty_coeff();

    for (poly, value) in f_poly_total
        .iter_mut()
        .zip(f_poly_1.iter().zip(f_poly_2.iter()))
    {
        *poly = *value.0 + *value.1;
    }

    // Demonstrating the homomorphic property of KZG commitments. The sum of the KZG commitments
    // to the chunk polynomials should be the same as the KZG commitment to the total polynomial
    // that is a sum of the chunk polynomials
    let kzg_commitment_total = commit_kzg(&params, &f_poly_total);
    assert!(
        kzg_commitment_sum.to_affine() == kzg_commitment_total.to_affine(),
        "Commitments should be equal"
    );

    let poly_length = 1 << u64::from(K);

    // We're opening the resulting polynomial at x = 0 and expect the constant coefficient
    // to be equal to the grand total divided by the size of the polynomial
    // thanks to the univariate grand sum property.
    let challenge = Fp::ZERO;
    // The expected evaluation of the polynomial at x = 0 is the grand total divided by the size of the polynomial
    let eval =
        big_uint_to_fp(&(csv_total[BALANCES_INDEX - 1])) * Fp::from(poly_length).invert().unwrap();
    let kzg_proof = create_naive_kzg_proof::<KZGCommitmentScheme<Bn256>>(
        &params,
        &domain,
        &f_poly_total,
        challenge,
        eval,
    );

    // KZG proof verification demonstrates that we can successfully verify the grand total
    // after building the total KZG commitment from the chunk commitments
    assert!(
        verify_kzg_proof(&params, kzg_commitment_sum, kzg_proof, &challenge, &eval),
        "KZG proof verification failed"
    );
    assert!(
        !verify_kzg_proof(
            &params,
            kzg_commitment_sum,
            kzg_proof,
            &challenge,
            &big_uint_to_fp(&BigUint::from(123u32)),
        ),
        "Invalid proof verification should fail"
    );

    Ok(())
}
