use crate::circuits::merkle_sum_tree::MerkleSumTreeCircuit;
use crate::merkle_sum_tree::{big_int_to_fp, MerkleProof};
use ark_std::{end_timer, start_timer};
use crate::circuits::merkle_sum_tree::MerkleSumTreeCircuit;
use crate::merkle_sum_tree::{big_int_to_fp, MerkleProof};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;
use std::fs::File;

pub fn instantiate_circuit<const MST_WIDTH: usize, const N_ASSETS: usize>(
    assets_sum: [Fp; N_ASSETS],
    proof: MerkleProof<N_ASSETS>,
) -> MerkleSumTreeCircuit<MST_WIDTH, N_ASSETS> {
    MerkleSumTreeCircuit {
        leaf_hash: proof.entry.compute_leaf().hash,
        leaf_balances: proof
            .entry
            .balances()
            .iter()
            .map(big_int_to_fp)
            .collect::<Vec<_>>(),
        path_element_hashes: proof.sibling_hashes,
        path_element_balances: proof.sibling_sums,
        path_indices: proof.path_indices,
        assets_sum: assets_sum.to_vec(),
        root_hash: proof.root_hash,
    }
}

pub fn instantiate_empty_circuit<const MST_WIDTH: usize, const N_ASSETS: usize>(
    levels: usize,
) -> MerkleSumTreeCircuit<MST_WIDTH, N_ASSETS> {
    MerkleSumTreeCircuit {
        leaf_hash: Fp::zero(),
        leaf_balances: Vec::new(),
        path_element_hashes: vec![Fp::zero(); levels],
        path_element_balances: vec![[Fp::zero(); N_ASSETS]; levels],
        path_indices: vec![Fp::zero(); levels],
        assets_sum: vec![Fp::zero(); N_ASSETS],
        root_hash: Fp::zero(),
    }
}

pub fn generate_setup_params(levels: usize) -> ParamsKZG<Bn256> {
    // 2^k is the number of rows for the circuit. We choos 27 levels as upper bound for the merkle sum tree
    let k = match levels {
        4..=11 => 9,
        12..=23 => 10,
        24..=27 => 11,
        _ => 0,
    };

    let ptau_path = format!("ptau/hermez-raw-{}", k);

    let metadata = std::fs::metadata(ptau_path.clone());

    if metadata.is_err() {
        println!("ptau file not found, generating a trusted setup of our own. If needed, download the ptau from https://github.com/han0110/halo2-kzg-srs");
        ParamsKZG::<Bn256>::setup(k, OsRng)
    } else {
        println!("ptau file found");
        let mut params_fs = File::open(ptau_path).expect("couldn't load params");
        ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params")
    }
}

pub fn instantiate_circuit(assets_sum: Fp, proof: MerkleProof) -> MerkleSumTreeCircuit {

    MerkleSumTreeCircuit {
        leaf_hash: proof.entry.compute_leaf().hash,
        leaf_balance: big_int_to_fp(proof.entry.balance()),
        path_element_hashes: proof.sibling_hashes,
        path_element_balances: proof.sibling_sums,
        path_indices: proof.path_indices,
        assets_sum,
        root_hash: proof.root_hash,
    }
}

pub fn instantiate_empty_circuit(levels: usize) -> MerkleSumTreeCircuit {
    MerkleSumTreeCircuit {
        leaf_hash: Fp::zero(),
        leaf_balance: Fp::zero(),
        path_element_hashes: vec![Fp::zero(); levels],
        path_element_balances: vec![Fp::zero(); levels],
        path_indices: vec![Fp::zero(); levels],
        assets_sum: Fp::zero(),
        root_hash: Fp::zero(),
    }
}

pub fn full_prover<C: Circuit<Fp>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_input: &[Fp],
) -> Vec<u8> {
    let pf_time = start_timer!(|| "Creating proof");

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(
        params,
        pk,
        &[circuit],
        &[&[public_input]],
        OsRng,
        &mut transcript,
    )
    .expect("prover should not fail");
    let proof = transcript.finalize();
    end_timer!(pf_time);
    proof
}

pub fn full_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    public_input: &[Fp],
) -> bool {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(
        verifier_params,
        vk,
        strategy,
        &[&[public_input]],
        &mut transcript,
    )
    .is_ok()
}
