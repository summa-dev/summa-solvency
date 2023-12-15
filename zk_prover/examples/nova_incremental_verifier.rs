use std::{
    collections::HashMap,
    env::current_dir,
    fs::File,
    io::{BufRead, BufReader},
    time::Instant,
};

use ff::{Field, PrimeField};
use nova_scotia::{
    circom::reader::load_r1cs, create_public_params, create_recursive_circuit, FileLocation, F, S,
};
use nova_snark::{provider, CompressedSNARK, PublicParams};
use num_bigint::BigUint;
use serde_json::json;
use summa_solvency::merkle_sum_tree::utils::big_intify_username;

const N_CURRENCIES: usize = 2;

/// In this scenario the Exchange is generating an incremental inclusion proof for a user after 3 rounds.
/// It means that starting from this proof, the user can verify their correct inclusion in the Liabilities Tree for each round up to round 3 in a single proof.
///
fn run_test(circuit_filepath: String, witness_gen_filepath: String) {
    // Liabilities State represents the state of the Liabilities Tree at each step. H(prev_state, root) = liabiltiies_state. It starts at 0
    // The Liabilties State is submitted to the smart contract at each step as part of the Proof of Solvency (not included in this example)
    let liabilities_state_0 = Fr::from_str("0").unwrap();

    // Merkle Proof represents the inclusion proof for the user 0 for each state
    let merkle_proof_1 = build_merkle_proof("../csv/states/entry_16_1.csv".to_string(), 0).unwrap();
    let liabilities_state_1 =
        build_liabilities_state_cur(liabilities_state_0, merkle_proof_1.root.hash);

    let merkle_proof_2 = build_merkle_proof("../csv/states/entry_16_2.csv".to_string(), 0).unwrap();
    let liabilities_state_2 =
        build_liabilities_state_cur(liabilities_state_1, merkle_proof_2.root.hash);

    let merkle_proof_3 = build_merkle_proof("../csv/states/entry_16_3.csv".to_string(), 0).unwrap();
    let liabilities_state_3 =
        build_liabilities_state_cur(liabilities_state_2, merkle_proof_3.root.hash);

    // At state 3, the user is requesting an incremental inclusion proof for the first time. The CEX generates it.
    type G1 = provider::bn256_grumpkin::bn256::Point;
    type G2 = provider::bn256_grumpkin::grumpkin::Point;

    println!(
        "Running test with witness generator: {} and group: {}",
        witness_gen_filepath,
        std::any::type_name::<G1>()
    );

    let iteration_count = 3;
    let root = current_dir().unwrap();

    let circuit_file = root.join(circuit_filepath);
    let r1cs = load_r1cs::<G1, G2>(&FileLocation::PathBuf(circuit_file));
    let witness_generator_file = root.join(witness_gen_filepath);

    let pp: PublicParams<G1, G2, _, _> = create_public_params(r1cs.clone());

    println!(
        "Number of constraints per step (primary circuit): {}",
        pp.num_constraints().0
    );
    println!(
        "Number of constraints per step (secondary circuit): {}",
        pp.num_constraints().1
    );

    println!(
        "Number of variables per step (primary circuit): {}",
        pp.num_variables().0
    );
    println!(
        "Number of variables per step (secondary circuit): {}",
        pp.num_variables().1
    );

    // Build the private inputs for each step circuit
    let merkle_proofs = vec![
        merkle_proof_1.clone(),
        merkle_proof_2.clone(),
        merkle_proof_3.clone(),
    ];

    let usernames = merkle_proofs
        .iter()
        .map(|proof| proof.username.clone())
        .collect::<Vec<String>>();

    let user_balances = merkle_proofs
        .iter()
        .map(|proof| proof.user_balances.clone())
        .collect::<Vec<Vec<String>>>();

    let path_element_hashes = merkle_proofs
        .iter()
        .map(|proof| proof.path_element_hashes.clone())
        .collect::<Vec<Vec<String>>>();

    let path_element_balances = merkle_proofs
        .iter()
        .map(|proof| proof.path_element_balances.clone())
        .collect::<Vec<Vec<Vec<String>>>>();

    let path_indices = merkle_proofs
        .iter()
        .map(|proof| proof.path_indices.clone())
        .collect::<Vec<Vec<String>>>();

    let mut private_inputs = Vec::new();
    for i in 0..iteration_count {
        let mut private_input = HashMap::new();
        private_input.insert("username".to_string(), json!(usernames[i]));
        private_input.insert("user_balances".to_string(), json!(user_balances[i]));
        private_input.insert(
            "path_element_hashes".to_string(),
            json!(path_element_hashes[i]),
        );
        private_input.insert(
            "path_element_balances".to_string(),
            json!(path_element_balances[i]),
        );
        private_input.insert("path_indices".to_string(), json!(path_indices[i]));
        private_inputs.push(private_input);
    }

    // The start public input is [user_state_cur, liabilities_state_cur] which are both 0 at state 0
    let start_public_input = [F::<G1>::from(0), F::<G1>::from(0)];

    println!("Creating a RecursiveSNARK...");
    let start = Instant::now();
    let recursive_snark = create_recursive_circuit(
        FileLocation::PathBuf(witness_generator_file.clone()),
        r1cs.clone(),
        private_inputs,
        start_public_input.to_vec(),
        &pp,
    )
    .unwrap();
    println!("RecursiveSNARK creation took {:?}", start.elapsed());

    // TODO: empty?
    let z0_secondary = [F::<G2>::from(0)];

    // verify the recursive SNARK
    println!("Verifying a RecursiveSNARK...");
    let start = Instant::now();
    let res = recursive_snark.verify(&pp, iteration_count, &start_public_input, &z0_secondary);
    println!(
        "RecursiveSNARK::verify: {:?}, took {:?}",
        res,
        start.elapsed()
    );
    assert!(res.is_ok());

    let z_last = res.unwrap().0;

    // The user has to check the correctness of the liabilities after state 3 according to the Incremental Proof
    // The user checks that this is equal to the liabilities state committed by the CEX at state 3
    println!(
        "liabilities_state_cur at state 3 as output of the Incremental Proof {:?}",
        z_last[1]
    );
    println!(
        "liabilities state committed by the CEX at state 3 {:?}",
        liabilities_state_3
    );

    // The user also has to check the correctness of the user state after state 3 according to the Incremental Proof
    // The user checks that this is equal to the locally computed user_state_cur
    let user_state_0 = Fr::from_str("0").unwrap();

    let user_state_1 = build_user_state_cur(
        user_state_0,
        merkle_proof_1.username,
        merkle_proof_1.user_balances,
    );
    let user_state_2 = build_user_state_cur(
        user_state_1,
        merkle_proof_2.username,
        merkle_proof_2.user_balances,
    );
    let user_state_3 = build_user_state_cur(
        user_state_2,
        merkle_proof_3.username,
        merkle_proof_3.user_balances,
    );

    println!(
        "user_state_cur at state 3 as output of the Incremental Proof {:?}",
        z_last[0]
    );
    println!(
        "user state computed locally by the user starting from their logs {:?}",
        user_state_3
    );

    // produce a compressed SNARK
    println!("Generating a CompressedSNARK using Spartan with IPA-PC...");
    let start = Instant::now();
    let (pk, vk) = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::setup(&pp).unwrap();
    let res = CompressedSNARK::<_, _, _, _, S<G1>, S<G2>>::prove(&pp, &pk, &recursive_snark);
    println!(
        "CompressedSNARK::prove: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
    let compressed_snark = res.unwrap();

    // verify the compressed SNARK
    println!("Verifying a CompressedSNARK...");
    let start = Instant::now();
    let res = compressed_snark.verify(
        &vk,
        iteration_count,
        start_public_input.to_vec(),
        z0_secondary.to_vec(),
    );
    println!(
        "CompressedSNARK::verify: {:?}, took {:?}",
        res.is_ok(),
        start.elapsed()
    );
    assert!(res.is_ok());
}

fn main() {
    let circuit_filepath = "examples/build/incremental_mst_inclusion.r1cs".to_string();
    let witness_gen_filepath =
        "examples/build/incremental_mst_inclusion_js/incremental_mst_inclusion.wasm".to_string();
    run_test(circuit_filepath.clone(), witness_gen_filepath);
}

use num_traits::Num;
use poseidon_rs::{Fr, Poseidon};

// Note that we cannot reuse the MerkleSumTree implementation from zk_prover because it is not compatible with circom's Poseidon Hasher
#[derive(Clone, Debug)]
struct Node<const N_CURRENCIES: usize> {
    hash: Fr,
    balance: [Fr; N_CURRENCIES],
}

#[derive(Clone, Debug)]
struct MerkleProof<const N_CURRENCIES: usize> {
    username: String,
    user_balances: Vec<String>,
    path_element_hashes: Vec<String>,
    path_element_balances: Vec<Vec<String>>,
    path_indices: Vec<String>,
    root: Node<N_CURRENCIES>,
}

impl<const N_CURRENCIES: usize> Node<N_CURRENCIES> {
    /// Constructs a new Node given left and right child hashes.
    fn new(
        left: &Node<N_CURRENCIES>,
        right: &Node<N_CURRENCIES>,
        hasher: &Poseidon,
    ) -> Node<N_CURRENCIES> {
        let mut input = vec![left.hash];
        input.extend(left.balance);
        input.push(right.hash);
        input.extend(right.balance);

        let mut balance = vec![];

        // iterate over N_CURRENCIES
        for i in 0..N_CURRENCIES {
            let mut sum = Fr::from_str("0").unwrap();
            sum.add_assign(&left.balance[i]);
            sum.add_assign(&right.balance[i]);

            balance.push(sum);
        }

        Node {
            hash: hasher.hash(input).unwrap(),
            balance: balance.try_into().unwrap(),
        }
    }
}

/// Generates a Merkle proof of inclusion for a leaf at a given index
fn build_merkle_proof(
    csv_filepath: String,
    user_index: usize,
) -> Option<MerkleProof<N_CURRENCIES>> {
    let file = File::open(csv_filepath).expect("Unable to open file");
    let reader = BufReader::new(file);

    let mut leaves = vec![];

    let hasher = Poseidon::new();

    let mut captured_username = String::new();
    let mut captured_user_balances = vec![];

    for (idx, line) in reader.lines().skip(1).enumerate() {
        // skipping header
        let line = line.expect("Unable to read line");
        let data: Vec<&str> = line.split(';').collect();

        if data.len() != 2 {
            continue; // Invalid line format
        }

        let username = big_intify_username(data[0]).to_string();

        // convert balances to Fr
        let balances: Vec<Fr> = data[1]
            .split(',')
            .map(|balance_str| Fr::from_str(balance_str).unwrap())
            .collect();

        assert_eq!(balances.len(), N_CURRENCIES);

        // capture user's data if the index matches
        if idx == user_index {
            captured_username = username.to_string();
            captured_user_balances = data[1].split(',').map(|s| s.to_string()).collect();
        }

        let username = Fr::from_str(&username).unwrap();

        // create a vector input that takes the username and the balances
        let mut input = vec![username];
        input.extend(balances.clone());

        let hash = hasher.hash(input).unwrap();

        leaves.push(Node {
            hash,
            balance: balances.try_into().unwrap(),
        });
    }

    let mut current_level = leaves.clone();

    let mut path_element_hashes = vec![];
    let mut path_element_balances = vec![];
    let mut path_indices = vec![];

    while current_level.len() > 1 {
        let mut next_level = vec![];

        for i in (0..current_level.len()).step_by(2) {
            let left = &current_level[i];
            let right = if i + 1 < current_level.len() {
                &current_level[i + 1]
            } else {
                &current_level[i]
            };

            if user_index == i {
                path_element_hashes.push(fr_to_string(right.hash).unwrap());
                path_element_balances.push(
                    right
                        .balance
                        .iter()
                        .map(|fr| fr_to_string(*fr).unwrap())
                        .collect(),
                );
                path_indices.push("0".to_string()); // 0 means that the right element is the path element
            } else if user_index == i + 1 {
                path_element_hashes.push(fr_to_string(left.hash).unwrap());
                path_element_balances.push(
                    left.balance
                        .iter()
                        .map(|fr| fr_to_string(*fr).unwrap())
                        .collect(), // 1 means that the left element is the path element
                );
                path_indices.push("1".to_string());
            }

            let parent = Node::new(left, right, &hasher);
            next_level.push(parent);
        }

        current_level = next_level;
    }

    // fetch the root
    let root = current_level[0].clone();

    Some(MerkleProof {
        username: captured_username,
        user_balances: captured_user_balances,
        path_element_hashes,
        path_element_balances,
        path_indices,
        root,
    })
}

/// The current liabilities state is obtained by hashing the previous liabilities state and the root hash of the current liabilities tree
fn build_liabilities_state_cur(liabilities_state_prev: Fr, root_hash: Fr) -> Fr {
    let hasher = Poseidon::new();

    let mut input = vec![liabilities_state_prev];
    input.push(root_hash);

    hasher.hash(input).unwrap()
}

/// The current user state is obtained by hashing the previous user state and the user leaf hash of the current liabilities tree
fn build_user_state_cur(user_state_prev: Fr, username: String, user_balances: Vec<String>) -> Fr {
    let hasher = Poseidon::new();

    let leaf_hash = {
        let mut input = vec![Fr::from_str(&username).unwrap()];
        input.extend(
            user_balances
                .iter()
                .map(|balance_str| Fr::from_str(balance_str).unwrap()),
        );

        hasher.hash(input).unwrap()
    };

    let mut input = vec![user_state_prev];
    input.push(leaf_hash);

    hasher.hash(input).unwrap()
}

/// Converts a Fr to a its decimal string representation
fn fr_to_string(v: Fr) -> Option<String> {
    // Convert v to string
    let s = v.to_string();

    // Extract the hexadecimal portion from the string.
    // The pattern "Fr(" and ")" should surround the hexadecimal.
    if let Some(hex_start) = s.find("Fr(0x") {
        let hex_end = s.rfind(')')?;
        let hex_str = &s[hex_start + 5..hex_end];

        // Convert the hexadecimal to a decimal string.
        let decimal_str = BigUint::from_str_radix(hex_str, 16)
            .ok()
            .map(|bigint| bigint.to_str_radix(10))
            .unwrap();

        return Some(decimal_str);
    }
    None
}
