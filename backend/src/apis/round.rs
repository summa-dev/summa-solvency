use ethers::types::{Bytes, U256};
use halo2_proofs::{
    arithmetic::{best_fft, Field},
    halo2curves::{
        bn256::{Bn256, Fr as Fp, G1Affine, G2Affine},
        group::{cofactor::CofactorCurveAffine, Curve},
    },
    plonk::{AdviceSingle, VerifyingKey},
    poly::{
        kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
        Coeff,
    },
    transcript::TranscriptRead,
};
use halo2_solidity_verifier::Keccak256Transcript;
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::contracts::signer::SummaSigner;
use summa_solvency::utils::amortized_kzg::{create_naive_kzg_proof, verify_kzg_proof};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KZGProof {
    proof_calldata: Bytes,
    input_values: Vec<U256>,
    challenge_s_g2: Option<Vec<U256>>,
}

impl KZGProof {
    pub fn get_input_values(&self) -> &Vec<U256> {
        &self.input_values
    }

    pub fn get_proof(&self) -> &Bytes {
        &self.proof_calldata
    }

    pub fn get_challenge(&self) -> &Option<Vec<U256>> {
        &self.challenge_s_g2
    }
}

/// The `Round` struct represents a single operational cycle within the Summa Solvency protocol.
///
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of currencies for which solvency is verified in this round.
/// * `N_USERS`: The number of users involved in this round of the protocol.
///
/// These parameters are used for initializing the `UnivariateGrandSum` circuit within the `Snapshot` struct.
///
/// # Fields
///
/// * `timestamp`: A Unix timestamp marking the initiation of this round. It serves as a temporal reference point
///   for the operations carried out in this phase of the protocol.
/// * `snapshot`: A `Snapshot` struct capturing the round's state, including user identities and balances.
/// * `signer`: A reference to a `SummaSigner`, the entity responsible for signing transactions with the Summa contract in this round.
///
pub struct Round<'a, const N_CURRENCIES: usize, const N_USERS: usize> {
    timestamp: u64,
    snapshot: Snapshot<N_CURRENCIES, N_USERS>,
    signer: &'a SummaSigner,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> Round<'_, N_CURRENCIES, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new(
        signer: &SummaSigner,
        zk_snark_proof: Vec<u8>,
        advice_polys: AdviceSingle<G1Affine, Coeff>,
        params: ParamsKZG<Bn256>,
        verifying_key: VerifyingKey<G1Affine>,
        timestamp: u64,
    ) -> Round<'_, N_CURRENCIES, N_USERS> {
        Round {
            timestamp,
            snapshot: Snapshot::<N_CURRENCIES, N_USERS>::new(
                zk_snark_proof,
                advice_polys,
                params,
                verifying_key,
            ),
            signer,
        }
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    pub async fn dispatch_commitment(&mut self) -> Result<(), Box<dyn Error>> {
        let grand_sum_proof = self.snapshot.generate_grand_sum_proof().unwrap();
        let submit_tx = self.signer.submit_commitment(
            Bytes::from(self.snapshot.zk_snark_proof.clone()),
            grand_sum_proof.proof_calldata,
            grand_sum_proof.input_values,
            self.timestamp.into(),
        );

        submit_tx.await
    }

    pub fn get_proof_of_inclusion(&self, user_index: usize) -> Result<KZGProof, &'static str> {
        self.snapshot.generate_proof_of_inclusion(user_index)
    }
}

/// The `Snapshot` struct represents the state of database that contains users balance on holds by Custodians at a specific moment.
///
/// # Fields
///
/// * `zk_snark_proof`: The zk-SNARK proof for the round, which is used to verify the validity of the round's commitments.
/// * `advice_polys`: Composed of the unblinded advice polynomial, `advice_poly`, and the polynomials of blind factors, `advice_blind`.
/// * `params`: The parameters for the KZG commitment scheme.
/// * `verifying_key`: The verifying key for getting domains, which is used for generating inclusion proofs.
///
pub struct Snapshot<const N_CURRENCIES: usize, const N_USERS: usize> {
    zk_snark_proof: Vec<u8>,
    advice_polys: AdviceSingle<G1Affine, Coeff>,
    params: ParamsKZG<Bn256>,
    verifying_key: VerifyingKey<G1Affine>,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> Snapshot<N_CURRENCIES, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new(
        zk_snark_proof: Vec<u8>,
        advice_polys: AdviceSingle<G1Affine, Coeff>,
        params: ParamsKZG<Bn256>,
        verifying_key: VerifyingKey<G1Affine>,
    ) -> Self {
        Snapshot {
            zk_snark_proof,
            advice_polys,
            params,
            verifying_key,
        }
    }

    pub fn generate_grand_sum_proof(&self) -> Result<KZGProof, &'static str> {
        let challenge = Fp::zero();
        let (proof_calldata, input_values) = self.generate_kzg_proof(None, challenge).unwrap();

        Ok(KZGProof {
            proof_calldata,
            input_values,
            challenge_s_g2: None,
        })
    }

    pub fn generate_proof_of_inclusion(&self, user_index: usize) -> Result<KZGProof, &'static str> {
        let omega = self.verifying_key.get_domain().get_omega();
        let challenge = omega.pow_vartime([user_index as u64]);
        let (proof_calldata, input_values) = self
            .generate_kzg_proof(Some(user_index), challenge)
            .unwrap();

        // Prepare S_G2 points with the challenge for proof verification on the KZG Solidity verifier.
        let s_g2 = -self.params.s_g2() + (G2Affine::generator() * challenge);
        let s_g2_affine = s_g2.to_affine();

        let s_g2_point = vec![
            U256::from_little_endian(s_g2_affine.x.c1.to_bytes().as_slice()),
            U256::from_little_endian(s_g2_affine.x.c0.to_bytes().as_slice()),
            U256::from_little_endian(s_g2_affine.y.c1.to_bytes().as_slice()),
            U256::from_little_endian(s_g2_affine.y.c0.to_bytes().as_slice()),
        ];

        Ok(KZGProof {
            proof_calldata,
            input_values,
            challenge_s_g2: Some(s_g2_point),
        })
    }

    fn generate_kzg_proof(
        &self,
        user_index: Option<usize>,
        challenge: Fp,
    ) -> Result<(Bytes, Vec<U256>), &'static str> {
        let domain = self.verifying_key.get_domain();
        let omega = domain.get_omega();

        let mut opening_proofs = Vec::new();
        let mut input_values = Vec::new();

        // Evaluate the commitments from the SNARK proof
        let mut kzg_commitments = Vec::with_capacity(N_CURRENCIES);
        let mut transcript = Keccak256Transcript::new(self.zk_snark_proof.as_slice());
        for _ in 0..(N_CURRENCIES + 1) {
            let point: G1Affine = transcript.read_point().unwrap();
            kzg_commitments.push(point);
        }

        // If the user index is None, assign 1 or else 0, for skipping the usename polynomial.
        let start_index = user_index.map_or(1, |_| 0);

        for column_index in start_index..N_CURRENCIES + 1 {
            let f_poly = self.advice_polys.advice_polys.get(column_index).unwrap();

            // Perform iDFT to obtain the actual value that is encoded in the polynomial.
            let mut vec_f_poly = f_poly.to_vec();
            best_fft(&mut vec_f_poly, omega, f_poly.len().trailing_zeros());

            let z = if let Some(user_index) = user_index {
                let _z = vec_f_poly[user_index];
                input_values.push(U256::from_little_endian(&_z.to_bytes()));
                _z
            } else {
                let total_balance: Fp = vec_f_poly.iter().sum();
                input_values.push(U256::from_little_endian(&total_balance.to_bytes()));
                total_balance * Fp::from(f_poly.len() as u64).invert().unwrap()
            };

            let kzg_proof = create_naive_kzg_proof::<KZGCommitmentScheme<Bn256>>(
                &self.params,
                domain,
                f_poly,
                challenge,
                z,
            );

            if !verify_kzg_proof(
                &self.params,
                kzg_commitments[column_index].to_curve(),
                kzg_proof,
                &challenge,
                &z,
            ) {
                return Err("KZG proof verification failed");
            }

            // Convert the KZG proof to an affine point and serialize it to bytes.
            let kzg_proof_affine = kzg_proof.to_affine();
            let mut kzg_proof_affine_x = kzg_proof_affine.x.to_bytes();
            let mut kzg_proof_affine_y = kzg_proof_affine.y.to_bytes();
            kzg_proof_affine_x.reverse();
            kzg_proof_affine_y.reverse();

            opening_proofs.push([kzg_proof_affine_x, kzg_proof_affine_y].concat());
        }

        Ok((Bytes::from(opening_proofs.concat()), input_values))
    }
}
