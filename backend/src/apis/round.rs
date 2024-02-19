use ethers::types::{Bytes, U256};
use halo2_proofs::{
    arithmetic::{best_fft, Field},
    halo2curves::{
        bn256::{Bn256, G1Affine},
        group::Curve,
    },
    plonk::{AdviceSingle, VerifyingKey},
    poly::{
        kzg::commitment::{KZGCommitmentScheme, ParamsKZG},
        Coeff,
    },
};
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::contracts::signer::SummaSigner;
use summa_solvency::utils::amortized_kzg::{commit_kzg, create_naive_kzg_proof, verify_kzg_proof};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KZGInclusionProof {
    public_inputs: Vec<U256>,
    proof_calldata: Bytes,
}

impl KZGInclusionProof {
    pub fn get_public_inputs(&self) -> &Vec<U256> {
        &self.public_inputs
    }

    pub fn get_proof(&self) -> &Bytes {
        &self.proof_calldata
    }
}

/// The `Round` struct represents a single operational cycle within the Summa Solvency protocol.
///
/// # Type Parameters
///
/// * `N_CURRENCIES`: The number of currencies for which solvency is verified in this round.
/// * `N_POINTS`: The number of points in the `UnivariateGrandSum` circuit, which is `N_CURRENCIES + 1`.
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
pub struct Round<'a, const N_CURRENCIES: usize, const N_POINTS: usize, const N_USERS: usize> {
    timestamp: u64,
    snapshot: Snapshot<N_CURRENCIES, N_POINTS, N_USERS>,
    signer: &'a SummaSigner,
}

impl<const N_CURRENCIES: usize, const N_POINTS: usize, const N_USERS: usize>
    Round<'_, N_CURRENCIES, N_POINTS, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new<'a>(
        signer: &'a SummaSigner,
        advice_polys: AdviceSingle<G1Affine, Coeff>,
        params: ParamsKZG<Bn256>,
        verifying_key: VerifyingKey<G1Affine>,
        timestamp: u64,
    ) -> Result<Round<'a, N_CURRENCIES, N_POINTS, N_USERS>, Box<dyn Error>> {
        Ok(Round {
            timestamp,
            snapshot: Snapshot::<N_CURRENCIES, N_POINTS, N_USERS>::new(
                advice_polys,
                params,
                verifying_key,
            )
            .unwrap(),
            signer: &signer,
        })
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    // TODO: What will be the commit on the V2?
    pub async fn dispatch_commitment(&mut self) -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    pub fn get_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<KZGInclusionProof, &'static str>
    where
        [(); N_CURRENCIES + 1]: Sized,
    {
        // Iterate unblinded advice polynomials evaluate balances array
        Ok(self
            .snapshot
            .generate_proof_of_inclusion(user_index)
            .unwrap())
    }
}

/// The `Snapshot` struct represents the state of database that contains users balance on holds by Custodians at a specific moment.
///
/// # Fields
///
/// * `advice_polys`: Composed of the unblinded advice polynomial, `advice_poly`, and the polynomials of blind factors, `advice_blind`.
/// * `params`: The parameters for the KZG commitment scheme.
/// * `verifying_key`: The verifying key for getting domains, which is used for generating inclusion proofs.
///
pub struct Snapshot<const N_CURRENCIES: usize, const N_POINTS: usize, const N_USERS: usize> {
    advice_polys: AdviceSingle<G1Affine, Coeff>,
    params: ParamsKZG<Bn256>,
    verifying_key: VerifyingKey<G1Affine>,
}

impl<const N_CURRENCIES: usize, const N_POINTS: usize, const N_USERS: usize>
    Snapshot<N_CURRENCIES, N_POINTS, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new(
        advice_polys: AdviceSingle<G1Affine, Coeff>,
        params: ParamsKZG<Bn256>,
        verifying_key: VerifyingKey<G1Affine>,
    ) -> Result<Snapshot<N_CURRENCIES, N_POINTS, N_USERS>, Box<dyn Error>> {
        Ok(Snapshot {
            advice_polys,
            params,
            verifying_key,
        })
    }

    pub fn generate_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<KZGInclusionProof, &'static str>
    where
        [(); N_CURRENCIES + 1]: Sized, // TODO: check is this necessary to compile?
    {
        let domain = self.verifying_key.get_domain();
        let omega: halo2_proofs::halo2curves::grumpkin::Fq = domain.get_omega();

        let column_range = 0..N_CURRENCIES + 1;
        let mut opening_proofs = Vec::new();
        let challenge = omega.pow_vartime([user_index as u64]);

        for column_index in column_range {
            let f_poly = self.advice_polys.advice_polys.get(column_index).unwrap();
            let kzg_commitment = commit_kzg(&self.params, f_poly);

            // Do iDFT for getting value of polynomial
            let mut vec_f_poly = f_poly.to_vec();
            best_fft(&mut vec_f_poly, omega, f_poly.len().trailing_zeros());
            let z = vec_f_poly[user_index];

            let kzg_proof = create_naive_kzg_proof::<KZGCommitmentScheme<Bn256>>(
                &self.params,
                domain,
                f_poly,
                challenge,
                z,
            );

            assert!(
                verify_kzg_proof(&self.params, kzg_commitment, kzg_proof, &challenge, &z),
                "KZG proof verification failed for user {}",
                user_index
            );

            // Convert to affine point and serialize to bytes
            let kzg_proof_affine = kzg_proof.to_affine();
            let mut kzg_proof_affine_x = kzg_proof_affine.x.to_bytes();
            let mut kzg_proof_affine_y = kzg_proof_affine.y.to_bytes();
            kzg_proof_affine_x.reverse();
            kzg_proof_affine_y.reverse();

            opening_proofs.push([kzg_proof_affine_x, kzg_proof_affine_y].concat());
        }

        Ok(KZGInclusionProof {
            proof_calldata: Bytes::from(opening_proofs.concat()),
            public_inputs: Vec::<U256>::new(),
        })
    }
}
