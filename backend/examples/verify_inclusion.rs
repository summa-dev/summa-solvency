#![feature(generic_const_exprs)]
use halo2_proofs::halo2curves::{bn256::Fr as Fp, ff::PrimeField};
use num_bigint::BigUint;

use summa_backend::apis::round::Snapshot;
use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        utils::{full_verifier, generate_setup_artifacts},
    },
    merkle_sum_tree::Entry,
};

// The CEX may only provide `balances` and `username` to the user without `leaf_hash`.
// In this case, the user will have to generate `leaf_hash` themselves with this method.
fn generate_leaf_hash<const N_ASSETS: usize>(user_name: String, balances: Vec<usize>) -> Fp
where
    [usize; N_ASSETS + 1]: Sized,
{
    // Convert usize to BigInt for the `Entry` struct
    let balances_big_uint: Vec<BigUint> = balances.into_iter().map(BigUint::from).collect();

    let entry: Entry<N_ASSETS> =
        Entry::new(user_name, balances_big_uint.try_into().unwrap()).unwrap();

    entry.compute_leaf().hash
}

fn main() {
    const LEVELS: usize = 4;
    const N_ASSETS: usize = 2;
    const N_BYTES: usize = 8;

    let ptau_path = "./ptau/hermez-raw-11";
    let entry_csv_path = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";

    // CEX Generate the Merkle Sum Tree and then initialize the circuit.
    // Note that `signature_csv` is empty because this is only needed to generate π of Solvency, which is not the case here.
    let snapshot =
        Snapshot::<LEVELS, N_ASSETS, N_BYTES>::new(&entry_csv_path, &ptau_path, 1).unwrap();

    let inclusion_proof = snapshot.generate_proof_of_inclusion(0 as usize).unwrap();

    let encoded: Vec<u8> = bincode::serialize(&inclusion_proof.get_proof()).unwrap();

    // Most likely, the user will receive the proof file and load it for verification like the one below.
    //
    // let mut file = File::open("examples/entry_0_proof.bin").unwrap();
    // let mut encoded = Vec::new();
    // file.read_to_end(&mut encoded).unwrap();
    //
    // There are two public inputs: root_hash and leaf_hash.
    // The root_hash is publicly shared, but the leaf_hash is not.
    // Only the user can verify the leaf_hash using their name (username) and balances.
    // The verifier should have access to both the username and balances.
    //
    // root_hash = 0x02e021d9bf99c5bd7267488b6a7a5cf5f7d00222a41b6a9b971899c44089e0c5
    let root_hash = "1300633067792667740851197998552728163078912135282962223512949070409098715333";

    // When verifying the inclusion proof on the user side,
    // you have to load two files: `ptau` and `proof`.
    let proof: Vec<u8> = bincode::deserialize(&encoded[..]).unwrap();

    // Importantly, the user should verify the leaf hash using their username and balances.
    let user_name = "dxGaEAii".to_string();
    let balances_usize = vec![11888, 41163];

    // index 0 user's leaf_hash : 0x0e113acd03b98f0bab0ef6f577245d5d008cbcc19ef2dab3608aa4f37f72a407
    let leaf_hash = Fp::from_str_vartime(
        "6362822108736413915574850018842190920390136280184018644072260166743334495239",
    )
    .unwrap();

    // This is the purpose of the example
    // When the user receives their `leaf_hash`, the user must verify the `leaf_hash` from their `balances` and `username`.
    assert_eq!(
        leaf_hash,
        generate_leaf_hash::<N_ASSETS>(user_name.clone(), balances_usize.clone())
    );

    let mst_inclusion_circuit = MstInclusionCircuit::<LEVELS, N_ASSETS, N_BYTES>::init_empty();

    // The CEX can serve the params and vk by using the get_trusted_setup_for_mst_inclusion() method from the snapshot instance, as shown below:
    // let (params, _, vk) = snapshot.get_trusted_setup_for_mst_inclusion();
    //
    // However, on the user side, creating a snapshot is not possible due to the lack of the entry.csv and signature.csv files.
    // Therefore, we can generate the artifacts from the ptau file with a specified k, which is the same number used while generating the proof.
    let (params, _, vk) =
        generate_setup_artifacts(11, Some(ptau_path), mst_inclusion_circuit).unwrap();

    let verification_result: bool = full_verifier(
        &params,
        &vk,
        proof,
        vec![vec![leaf_hash, Fp::from_str_vartime(root_hash).unwrap()]],
    );

    // Given the proper inputs (`root_hash` and `leaf_hash`), the proof is valid.
    println!(
        "Verifying the proof result for User #0: {}",
        verification_result
    );
}
