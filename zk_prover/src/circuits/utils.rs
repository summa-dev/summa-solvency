use ark_std::{end_timer, start_timer};
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
use snark_verifier_sdk::CircuitExt;
use std::fs::File;

pub fn generate_setup_params(k: u32) -> ParamsKZG<Bn256> {
    let ptau_path = format!("ptau/hermez-raw-{}", k);

    let metadata = std::fs::metadata(ptau_path.clone());

    if metadata.is_err() {
        println!("ptau file not found, generating a trusted setup of our own. If needed, download the ptau from https://github.com/han0110/halo2-kzg-srs");
        // start timer
        let timer = start_timer!(|| "Creating params");
        let params = ParamsKZG::<Bn256>::setup(k, OsRng);
        end_timer!(timer);
        params
    } else {
        println!("ptau file found");
        let timer = start_timer!(|| "Creating params");
        let mut params_fs = File::open(ptau_path).expect("couldn't load params");
        let params = ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");
        end_timer!(timer);
        params
    }
}

pub fn full_prover<C: Circuit<Fp> + CircuitExt<Fp>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_inputs: Vec<Vec<Fp>>,
) -> Vec<u8> {
    let pf_time = start_timer!(|| "Creating proof");

    let instance: Vec<&[Fp]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(params, pk, &[circuit], instances, OsRng, &mut transcript)
    .expect("prover should not fail");
    let proof = transcript.finalize();
    end_timer!(pf_time);
    proof
}

pub fn full_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    public_inputs: Vec<Vec<Fp>>,
) -> bool {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

    let instance: Vec<&[Fp]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, vk, strategy, instances, &mut transcript)
    .is_ok()
}
