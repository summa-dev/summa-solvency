use ethers::types::{Bytes, U256};
use halo2_proofs::{halo2curves::bn256::G1Affine, plonk::AdviceSingle, poly::Coeff};
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::contracts::signer::SummaSigner;
use summa_solvency::circuits::{
    univariate_grand_sum::UnivariateGrandSum,
    utils::{generate_setup_artifacts, open_user_points, SetupArtifacts},
};

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
/// * `N_USERS`: The number of users involved in this round of the protocol.
///
/// /// These parameters are used for initializing the `UniVariantGrandSum` circuit within the `Snapshot` struct.
///
/// # Fields
///
/// * `timestamp`: A Unix timestamp marking the initiation of this round. It serves as a temporal reference point
///   for the operations carried out in this phase of the protocol.
/// * `snapshot`: A `Snapshot` struct capturing the round's state, including user identities and balances.
/// * `signer`: A reference to a `SummaSigner`, the entity responsible for signing transactions with the Summa contract in this round.
pub struct Round<'a, const N_CURRENCIES: usize, const N_USERS: usize> {
    timestamp: u64,
    snapshot: Snapshot<N_CURRENCIES, N_USERS>,
    signer: &'a SummaSigner,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> Round<'_, N_CURRENCIES, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new<'a>(
        signer: &'a SummaSigner,
        advice_polys: AdviceSingle<G1Affine, Coeff>,
        params_path: &str,
        timestamp: u64,
    ) -> Result<Round<'a, N_CURRENCIES, N_USERS>, Box<dyn Error>> {
        Ok(Round {
            timestamp,
            snapshot: Snapshot::<N_CURRENCIES, N_USERS>::new(advice_polys, params_path).unwrap(),
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
/// * `trusted_setup`: The trusted setup artifacts generated from the `UnivariateGrandSum` circuit.
///
/// TODO: make a link to explanation what the advice polynomial expression is.
pub struct Snapshot<const N_CURRENCIES: usize, const N_USERS: usize> {
    advice_polys: AdviceSingle<G1Affine, Coeff>,
    trusted_setup: SetupArtifacts,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> Snapshot<N_CURRENCIES, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new(
        advice_polys: AdviceSingle<G1Affine, Coeff>,
        params_path: &str,
    ) -> Result<Snapshot<N_CURRENCIES, N_USERS>, Box<dyn Error>> {
        let univariant_grand_sum_circuit =
            UnivariateGrandSum::<N_USERS, N_CURRENCIES>::init_empty();

        // get k from ptau file name
        let parts: Vec<&str> = params_path.split('-').collect();
        let last_part = parts.last().unwrap();
        let k = last_part.parse::<u32>().unwrap();

        let univariant_grand_sum_setup_artifcats: SetupArtifacts =
            generate_setup_artifacts(k, Some(params_path), univariant_grand_sum_circuit).unwrap();

        Ok(Snapshot {
            advice_polys,
            trusted_setup: univariant_grand_sum_setup_artifcats,
        })
    }

    pub fn generate_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<KZGInclusionProof, &'static str>
    where
        [(); N_CURRENCIES + 1]: Sized, // TODO: check is this necessary to compile?
    {
        let (params, _, vk) = &self.trusted_setup;
        let omega: halo2_proofs::halo2curves::grumpkin::Fq = vk.get_domain().get_omega();

        let column_range = 0..N_CURRENCIES + 1;
        let openings_batch_proof = open_user_points::<N_CURRENCIES>(
            &self.advice_polys.advice_polys,
            &self.advice_polys.advice_blinds,
            params,
            column_range,
            omega,
            user_index,
        );

        Ok(KZGInclusionProof {
            proof_calldata: Bytes::from(openings_batch_proof),
            public_inputs: Vec::<U256>::new(),
        })
    }
}
