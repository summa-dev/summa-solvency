use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
};

use ark_std::{end_timer, start_timer};
use ethers::types::U256;
use halo2_proofs::{
    arithmetic::eval_polynomial,
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine},
        ff::{PrimeField, WithSmallOrderMulGroup},
    },
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, Error, ProvingKey, VerifyingKey,
    },
    poly::{
        commitment::{Blind, CommitmentScheme, Params, ParamsProver, Prover, Verifier},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::{AccumulatorStrategy, SingleStrategy},
        },
        Coeff, Polynomial, ProverQuery, VerificationStrategy, VerifierQuery,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, TranscriptRead,
        TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;
use regex_simple::Regex;

use crate::utils::fp_to_big_uint;

/// Generate setup artifacts for a circuit of size `k`, where 2^k represents the number of rows in the circuit.
///
/// If the trusted setup parameters are not found, the function performs an unsafe trusted setup to generate the necessary parameters
/// If the provided `k` value is larger than the `k` value of the loaded parameters, an error is returned, as the provided `k` is too large.
/// Otherwise, if the `k` value is smaller than the `k` value of the loaded parameters, the parameters are downsized to fit the requested `k`.
pub fn generate_setup_artifacts<C: Circuit<Fp>>(
    k: u32,
    params_path: Option<&str>,
    circuit: C,
) -> Result<
    (
        ParamsKZG<Bn256>,
        ProvingKey<G1Affine>,
        VerifyingKey<G1Affine>,
    ),
    &'static str,
> {
    let mut params: ParamsKZG<Bn256>;

    match params_path {
        Some(path) => {
            let timer = start_timer!(|| "Creating params");
            let mut params_fs = File::open(path).expect("couldn't load params");
            params = ParamsKZG::<Bn256>::read(&mut params_fs).expect("Failed to read params");
            end_timer!(timer);

            if params.k() < k {
                return Err("k is too large for the given params");
            }

            if params.k() > k {
                let timer = start_timer!(|| "Downsizing params");
                params.downsize(k);
                end_timer!(timer);
            }
        }
        None => {
            let timer = start_timer!(|| "None Creating params");
            params = ParamsKZG::<Bn256>::setup(k, OsRng);
            end_timer!(timer);
        }
    }

    let vk = keygen_vk(&params, &circuit).expect("vk generation should not fail");
    let pk = keygen_pk(&params, vk.clone(), &circuit).expect("pk generation should not fail");

    Ok((params, pk, vk))
}

/// Generates a proof given the public setup, the proving key, the initialized circuit and its public inputs.
pub fn full_prover<C: Circuit<Fp>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    public_inputs: Vec<Vec<Fp>>,
) -> Vec<u8> {
    let pf_time = start_timer!(|| "Creating proof");

    let instance: Vec<&[Fp]> = public_inputs.iter().map(|input| &input[..]).collect();
    let instances = &[&instance[..]];

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    let result = create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(params, pk, &[circuit], instances, OsRng, &mut transcript);
    let result_unwrapped = result.unwrap();
    result_unwrapped.0.expect("prover should not fail");
    let advice_polys = result_unwrapped.1;
    let proof = transcript.finalize();

    // We know what column is the balance column
    let balance_column_index = 1;

    let mut readable_transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
        Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]).clone();

    //Read the commitment points for all the  advice polynomials from the proof transcript and put them into a vector
    let mut advice_commitments = Vec::new();
    for _ in 0..advice_polys[0].advice_polys.len() {
        let point = readable_transcript.read_point().unwrap();
        advice_commitments.push(point);
    }

    let balances_commitment = advice_commitments[balance_column_index];

    let challenge = Fp::zero();
    let kzg_proof = create_kzg_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
    >(
        params,
        advice_polys[0].advice_polys[balance_column_index].clone(),
        balances_commitment,
        advice_polys[0].advice_blinds[balance_column_index],
        challenge,
    );

    let kzg_verification_result = verify_kzg_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        Blake2bRead<_, _, Challenge255<_>>,
        AccumulatorStrategy<_>,
    >(params, balances_commitment, &kzg_proof, challenge);

    if kzg_verification_result {
        println!("KZG verified successfully");
    } else {
        println!("KZG verification failed");
    }

    //TODO next: make openings at "user" points
    end_timer!(pf_time);
    proof
}

fn create_kzg_proof<
    'params,
    Scheme: CommitmentScheme<Curve = halo2_proofs::halo2curves::bn256::G1Affine, Scalar = Fp>,
    P: Prover<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    T: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
>(
    params: &'params Scheme::ParamsProver,
    poly: Polynomial<<Scheme as CommitmentScheme>::Scalar, Coeff>,
    commitment_point: G1Affine,
    blind: Blind<Fp>,
    challenge: Fp,
) -> Vec<u8>
where
    Scheme::Scalar: WithSmallOrderMulGroup<3>,
{
    let mut transcript = T::init(vec![]);

    // Write the pre-existing commitment to the transcript
    transcript.write_point(commitment_point).unwrap();

    // Extract challenge from the transcript
    // let challenge = Fp::zero(); //transcript.squeeze_challenge();

    // Evaluate polynomial at the challenge
    let eval_at_challenge = eval_polynomial(&poly, challenge /*challenge.get_scalar()*/);
    println!(
        "wrote eval at challenge {:?}",
        fp_to_big_uint(eval_at_challenge)
    );
    // Write evaluation to transcript
    transcript.write_scalar(eval_at_challenge).unwrap();

    // Prepare prover query for the polynomial
    let queries = [ProverQuery::new(
        challenge, /*challenge.get_scalar()*/
        &poly, blind,
    )]
    .to_vec();

    // Create proof
    let prover = P::new(params);
    prover
        .create_proof(&mut OsRng, &mut transcript, queries)
        .unwrap();

    // Finalize transcript and return the proof
    transcript.finalize()
}

fn verify_kzg_proof<
    'a,
    'params,
    Scheme: CommitmentScheme<Curve = halo2_proofs::halo2curves::bn256::G1Affine, Scalar = Fp>,
    V: Verifier<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    T: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
    Strategy: VerificationStrategy<'params, Scheme, V, Output = Strategy>,
>(
    params: &'params Scheme::ParamsVerifier,
    commitment_point: G1Affine,
    proof: &'a [u8],
    challenge: Fp,
) -> bool
where
    Scheme::Scalar: WithSmallOrderMulGroup<3>,
{
    let mut transcript = T::init(proof);

    // Read the commitment from the transcript
    let read_commitment = transcript.read_point().unwrap();

    // Ensure the commitment matches the one provided
    if read_commitment != commitment_point {
        return false;
    }

    // Extract challenge from the transcript
    //let challenge = Fp::zero(); //transcript.squeeze_challenge();
    println!("challenge {:?}", fp_to_big_uint(challenge));

    // Read the polynomial evaluation from the transcript
    let eval_at_challenge = transcript.read_scalar().unwrap();
    println!(
        "read eval at challenge {:?}",
        fp_to_big_uint(eval_at_challenge)
    );

    println!(
        "grand sum {:?}",
        fp_to_big_uint(&Fp::from(512) * eval_at_challenge)
    );

    // Prepare verifier query for the commitment
    let queries = [VerifierQuery::new_commitment(
        &read_commitment,
        challenge, /* .get_scalar()*/
        eval_at_challenge,
    )];

    // Initialize the verifier
    let verifier = V::new(params);

    // Use the provided strategy for verification
    let strategy = Strategy::new(params);
    let strategy = strategy
        .process(|msm_accumulator| {
            verifier
                .verify_proof(&mut transcript, queries.iter().cloned(), msm_accumulator)
                .map_err(|_| Error::Opening)
        })
        .unwrap();

    // Return the result of the verification
    strategy.finalize()
}

/// Verifies a proof given the public setup, the verification key, the proof and the public inputs of the circuit.
pub fn full_verifier(
    params: &ParamsKZG<Bn256>,
    vk: &VerifyingKey<G1Affine>,
    proof: Vec<u8>,
    public_inputs: Vec<Vec<Fp>>,
) -> bool {
    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(params);
    let mut transcript: Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>> =
        Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);

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

/// Generate a solidity verifier contract from its yul code.
/// patterned after https://github.com/zkonduit/ezkl/blob/main/src/eth.rs#L326-L602
fn fix_verifier_sol(yul_code_path: PathBuf) -> Result<String, Box<dyn std::error::Error>> {
    let file = File::open(yul_code_path.clone())?;
    let reader = BufReader::new(file);

    let mut transcript_addrs: Vec<u32> = Vec::new();
    let mut modified_lines: Vec<String> = Vec::new();

    // convert calldataload 0x0 to 0x40 to read from pubInputs, and the rest
    // from proof
    let calldata_pattern = Regex::new(r"^.*(calldataload\((0x[a-f0-9]+)\)).*$")?;
    let mstore_pattern = Regex::new(r"^\s*(mstore\(0x([0-9a-fA-F]+)+),.+\)")?;
    let mstore8_pattern = Regex::new(r"^\s*(mstore8\((\d+)+),.+\)")?;
    let mstoren_pattern = Regex::new(r"^\s*(mstore\((\d+)+),.+\)")?;
    let mload_pattern = Regex::new(r"(mload\((0x[0-9a-fA-F]+))\)")?;
    let keccak_pattern = Regex::new(r"(keccak256\((0x[0-9a-fA-F]+))")?;
    let modexp_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x5, (0x[0-9a-fA-F]+), 0xc0, (0x[0-9a-fA-F]+), 0x20)")?;
    let ecmul_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x7, (0x[0-9a-fA-F]+), 0x60, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecadd_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x6, (0x[0-9a-fA-F]+), 0x80, (0x[0-9a-fA-F]+), 0x40)")?;
    let ecpairing_pattern =
        Regex::new(r"(staticcall\(gas\(\), 0x8, (0x[0-9a-fA-F]+), 0x180, (0x[0-9a-fA-F]+), 0x20)")?;
    let bool_pattern = Regex::new(r":bool")?;

    // Count the number of pub inputs
    let mut start = None;
    let mut end = None;
    for (i, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().starts_with("mstore(0x20") && start.is_none() {
            start = Some(i as u32);
        }

        if line.trim().starts_with("mstore(0x0") {
            end = Some(i as u32);
            break;
        }
    }

    let num_pubinputs = if let Some(s) = start {
        end.unwrap() - s
    } else {
        0
    };

    let mut max_pubinputs_addr = 0;
    if num_pubinputs > 0 {
        max_pubinputs_addr = num_pubinputs * 32 - 32;
    }
    // println!("max_pubinputs_addr {}", max_pubinputs_addr);

    let file = File::open(yul_code_path)?;
    let reader = BufReader::new(file);

    for line in reader.lines() {
        let mut line = line?;
        let m = bool_pattern.captures(&line);
        if m.is_some() {
            line = line.replace(":bool", "");
        }

        let m = calldata_pattern.captures(&line);
        if let Some(m) = m {
            let calldata_and_addr = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;

            if addr_as_num <= max_pubinputs_addr {
                let pub_addr = format!("{:#x}", addr_as_num + 32);
                // println!("pub_addr {}", pub_addr);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(pubInputs, {}))", pub_addr),
                );
            } else {
                let proof_addr = format!("{:#x}", addr_as_num - max_pubinputs_addr);
                // println!("proof_addr {}", proof_addr);
                line = line.replace(
                    calldata_and_addr,
                    &format!("mload(add(proof, {}))", proof_addr),
                );
            }
        }

        let m = mstore8_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = addr.parse::<u32>()?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore8(add(transcript, {})", transcript_addr),
            );
        }

        let m = mstoren_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = addr.parse::<u32>()?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = modexp_pattern.captures(&line);
        if let Some(m) = m {
            let modexp = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            line = line.replace(
                modexp,
                &format!(
                    "staticcall(gas(), 0x5, add(transcript, {}), 0xc0, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecmul_pattern.captures(&line);
        if let Some(m) = m {
            let ecmul = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecmul,
                &format!(
                    "staticcall(gas(), 0x7, add(transcript, {}), 0x60, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecadd_pattern.captures(&line);
        if let Some(m) = m {
            let ecadd = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecadd,
                &format!(
                    "staticcall(gas(), 0x6, add(transcript, {}), 0x80, add(transcript, {}), 0x40",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = ecpairing_pattern.captures(&line);
        if let Some(m) = m {
            let ecpairing = m.get(1).unwrap().as_str();
            let start_addr = m.get(2).unwrap().as_str();
            let result_addr = m.get(3).unwrap().as_str();
            let start_addr_as_num =
                u32::from_str_radix(start_addr.strip_prefix("0x").unwrap(), 16)?;
            let result_addr_as_num =
                u32::from_str_radix(result_addr.strip_prefix("0x").unwrap(), 16)?;

            let transcript_addr = format!("{:#x}", start_addr_as_num);
            let result_addr = format!("{:#x}", result_addr_as_num);
            transcript_addrs.push(start_addr_as_num);
            transcript_addrs.push(result_addr_as_num);
            line = line.replace(
                ecpairing,
                &format!(
                    "staticcall(gas(), 0x8, add(transcript, {}), 0x180, add(transcript, {}), 0x20",
                    transcript_addr, result_addr
                ),
            );
        }

        let m = mstore_pattern.captures(&line);
        if let Some(m) = m {
            let mstore = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr, 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mstore,
                &format!("mstore(add(transcript, {})", transcript_addr),
            );
        }

        let m = keccak_pattern.captures(&line);
        if let Some(m) = m {
            let keccak = m.get(1).unwrap().as_str();
            let addr = m.get(2).unwrap().as_str();
            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                keccak,
                &format!("keccak256(add(transcript, {})", transcript_addr),
            );
        }

        // mload can show up multiple times per line
        loop {
            let m = mload_pattern.captures(&line);
            if m.is_none() {
                break;
            }
            let mload = m.as_ref().unwrap().get(1).unwrap().as_str();
            let addr = m.as_ref().unwrap().get(2).unwrap().as_str();

            let addr_as_num = u32::from_str_radix(addr.strip_prefix("0x").unwrap(), 16)?;
            let transcript_addr = format!("{:#x}", addr_as_num);
            transcript_addrs.push(addr_as_num);
            line = line.replace(
                mload,
                &format!("mload(add(transcript, {})", transcript_addr),
            );
        }

        modified_lines.push(line);
    }

    // get the max transcript addr
    let max_transcript_addr = transcript_addrs.iter().max().unwrap() / 32;
    let mut contract = format!(
        "// SPDX-License-Identifier: MIT
    pragma solidity ^0.8.17;

    contract Verifier {{
        function verify(
            uint256[] memory pubInputs,
            bytes memory proof
        ) public view returns (bool) {{
            bool success = true;
            bytes32[{}] memory transcript;
            assembly {{
        ",
        max_transcript_addr
    )
    .trim()
    .to_string();

    // using a boxed Write trait object here to show it works for any Struct impl'ing Write
    // you may also use a std::fs::File here
    let write: Box<&mut dyn std::fmt::Write> = Box::new(&mut contract);

    for line in modified_lines[16..modified_lines.len() - 7].iter() {
        write!(write, "{}", line).unwrap();
    }
    writeln!(write, "}} return success; }} }}")?;
    Ok(contract)
}

/// Generate the proof Solidity calldata for a circuit
// pub fn gen_proof_solidity_calldata<C: Circuit<Fp>>(
//     params: &ParamsKZG<Bn256>,
//     pk: &ProvingKey<G1Affine>,
//     circuit: C,
// ) -> (Bytes, Vec<U256>) {
//     let instances = circuit.instances();

//     let pf_time = start_timer!(|| "Creating proof");
//     // To generate the proof calldata, make sure you have installed `solc`
//     let proof_calldata = gen_evm_proof_shplonk(params, pk, circuit, instances.clone());
//     end_timer!(pf_time);

//     let mut public_inputs = vec![];
//     let flattened_instances = instances.into_iter().flatten();

//     for val in flattened_instances {
//         public_inputs.push(field_element_to_solidity_calldata(val));
//     }

//     let solidity_proof_calldata = Bytes::from(proof_calldata);

//     (solidity_proof_calldata, public_inputs)
// }

/// Converts a field element to a Solidity calldata
pub fn field_element_to_solidity_calldata(field_element: Fp) -> U256 {
    let bytes = field_element.to_repr();
    let u = U256::from_little_endian(bytes.as_slice());
    u
}

/// Generates the solidity code for the verification contract starting from the yul code (yul_code_path) and writes it to sol_code_path
pub fn write_verifier_sol_from_yul(
    yul_code_path: &str,
    sol_code_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = fix_verifier_sol(PathBuf::from(yul_code_path))?;

    let mut f = File::create(sol_code_path)?;
    f.write_all(output.as_bytes())?;

    Ok(())
}

// Compiles the verification protocol and returns the cost estimate
// num_instance indicates the number of values in the instance column of the circuit. If there are more than one instance column, num_instance is equal to the sum of the number of values in each instance column.
// num_commitment is equal to the number of witness polynomials + the number of chunks of the quotient polynomial
// num_evaluation is equal to number of evaluations points of the polynomials that are part of the transcript
// num_msm indicates the number of msm operations that are part of the protocol
// num_pairing indicates the number of pairing operations that are part of the protocol
// pub fn get_verification_cost<C: Circuit<Fp>>(
//     params: &ParamsKZG<Bn256>,
//     pk: &ProvingKey<G1Affine>,
//     circuit: C,
// ) {
//     let protocol = compile(
//         params,
//         pk.get_vk(),
//         Config::kzg().with_num_instance(circuit.num_instance()),
//     );

//     let cost = PlonkSuccinctVerifier::<KzgAs<Bn256, Bdfg21>>::estimate_cost(&protocol);
//     dbg!(cost);
// }
