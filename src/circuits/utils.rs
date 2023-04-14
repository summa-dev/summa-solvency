use halo2_proofs::{
    halo2curves::bn256::{Fr as Fp, Bn256, G1Affine}, 
    poly::{
        commitment::ParamsProver,
        kzg::{
        commitment::{
            ParamsKZG,
            KZGCommitmentScheme,
        },
        strategy::SingleStrategy,
        multiopen::{ProverSHPLONK, VerifierSHPLONK}
        },
    },
    plonk::{
        create_proof, verify_proof, Circuit, ProvingKey, VerifyingKey
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use rand::rngs::OsRng;
use ark_std::{end_timer, start_timer};

pub fn full_prover <C: Circuit<Fp>> (
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
    >(params, pk, &[circuit], &[&[public_input]], OsRng, &mut transcript)
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
    >(verifier_params, vk, strategy, &[&[public_input]], &mut transcript)
        .is_ok()
}