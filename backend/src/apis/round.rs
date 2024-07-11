use plonkish_backend::{
    backend::hyperplonk::{HyperPlonkProverParam, HyperPlonkVerifierParam},
    halo2_curves::bn256::{Bn256, Fr as Fp},
    pcs::{multilinear::MultilinearKzg, Evaluation, PolynomialCommitmentScheme},
    poly::multilinear::MultilinearPolynomial,
    util::{
        transcript::{FieldTranscriptWrite, InMemoryTranscript, Keccak256Transcript},
        Itertools,
    },
};

use serde::{Deserialize, Serialize};
use std::error::Error;
use summa_hyperplonk::utils::uni_to_multivar_binary_index;

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct KZGProof {
    proof: Vec<u8>,
    input_values: Vec<Fp>,
    challenge: Option<Vec<Fp>>,
}

impl KZGProof {
    pub fn get_input_values(&self) -> &Vec<Fp> {
        &self.input_values
    }

    pub fn get_proof(&self) -> &Vec<u8> {
        &self.proof
    }

    pub fn get_challenge(&self) -> &Option<Vec<Fp>> {
        &self.challenge
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
///
pub struct Round<const N_CURRENCIES: usize, const N_USERS: usize> {
    timestamp: u64,
    snapshot: Snapshot<N_CURRENCIES, N_USERS>,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> Round<N_CURRENCIES, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new(
        zk_snark_proof: Vec<u8>,
        advice_polys: Vec<MultilinearPolynomial<Fp>>,
        prover_params: HyperPlonkProverParam<Fp, MultilinearKzg<Bn256>>,
        verifier_params: HyperPlonkVerifierParam<Fp, MultilinearKzg<Bn256>>,
        timestamp: u64,
    ) -> Round<N_CURRENCIES, N_USERS> {
        Round {
            timestamp,
            snapshot: Snapshot::<N_CURRENCIES, N_USERS>::new(
                zk_snark_proof,
                advice_polys,
                prover_params,
                verifier_params,
            ),
        }
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    /// This method returns the commitment proof and verification parameters for verifying proofs.
    /// Both the commitment and verification parameters should be posted publicly.
    #[allow(clippy::complexity)]
    pub fn gen_commitment_and_vp(
        &mut self,
    ) -> Result<(KZGProof, HyperPlonkVerifierParam<Fp, MultilinearKzg<Bn256>>), Box<dyn Error>>
    {
        let grand_sum_proof = self.snapshot.generate_grand_sum_proof().unwrap();
        Ok((grand_sum_proof, self.snapshot.verifier_params.clone()))
    }

    pub fn get_proof_of_inclusion(&self, user_index: usize) -> Result<KZGProof, &'static str> {
        self.snapshot.generate_proof_of_inclusion(user_index)
    }
}

/// The `Snapshot` struct represents the state of database that contains users balance on holds by Custodians at a specific moment.
///
/// # Fields
///
/// * `zk_snark_proof`: The zk-SNARK proof for the round, which is used to verify the validity of the round's commitment.
/// * `advice_polys`: Composed of the unblinded advice polynomial, `advice_poly`, and the polynomials of blind factors, `advice_blind`.
/// * `prover_params`: The parameters for generating KZG proofs, which are commitment and inclusions.
/// * `verifier_params`: The verifying params for verifying inclusion proofs.
///
pub struct Snapshot<const N_CURRENCIES: usize, const N_USERS: usize> {
    zk_snark_proof: Vec<u8>,
    advice_polys: Vec<MultilinearPolynomial<Fp>>,
    prover_params: HyperPlonkProverParam<Fp, MultilinearKzg<Bn256>>,
    verifier_params: HyperPlonkVerifierParam<Fp, MultilinearKzg<Bn256>>,
}

impl<const N_CURRENCIES: usize, const N_USERS: usize> Snapshot<N_CURRENCIES, N_USERS>
where
    [usize; N_CURRENCIES + 1]: Sized,
{
    pub fn new(
        zk_snark_proof: Vec<u8>,
        advice_polys: Vec<MultilinearPolynomial<Fp>>,
        prover_params: HyperPlonkProverParam<Fp, MultilinearKzg<Bn256>>,
        verifier_params: HyperPlonkVerifierParam<Fp, MultilinearKzg<Bn256>>,
    ) -> Self {
        Snapshot {
            zk_snark_proof,
            advice_polys,
            prover_params,
            verifier_params,
        }
    }

    pub fn generate_grand_sum_proof(&self) -> Result<KZGProof, &'static str> {
        let mut input_values = vec![Fp::zero(); N_CURRENCIES + 1];

        // First input values as instance would be zero like Summa V2
        for i in 1..N_CURRENCIES + 1 {
            let poly = self.advice_polys.get(i).unwrap();
            input_values[i] = poly.evals().iter().fold(Fp::zero(), |acc, x| acc + x);
        }

        Ok(KZGProof {
            proof: self.zk_snark_proof.clone(),
            input_values,
            challenge: None,
        })
    }

    pub fn generate_proof_of_inclusion(&self, user_index: usize) -> Result<KZGProof, &'static str> {
        let num_vars = self.prover_params.pcs.num_vars();
        let multivariate_challenge: Vec<Fp> = uni_to_multivar_binary_index(&user_index, num_vars);

        let mut kzg_transcript = Keccak256Transcript::new(());

        let mut transcript = Keccak256Transcript::from_proof((), self.zk_snark_proof.as_slice());

        let num_points = N_CURRENCIES + 1;
        let user_entry_commitments = MultilinearKzg::<Bn256>::read_commitments(
            &self.verifier_params.pcs,
            num_points,
            &mut transcript,
        )
        .unwrap();

        let user_entry_polynomials = self
            .advice_polys
            .iter()
            .take(num_points)
            .collect::<Vec<_>>();

        for binary_var in multivariate_challenge.iter() {
            kzg_transcript.write_field_element(binary_var).unwrap();
        }

        let evals = user_entry_polynomials
            .iter()
            .enumerate()
            .map(|(poly_idx, poly)| {
                Evaluation::new(poly_idx, 0, poly.evaluate(&multivariate_challenge))
            })
            .collect_vec();

        MultilinearKzg::<Bn256>::batch_open(
            &self.prover_params.pcs,
            user_entry_polynomials,
            &user_entry_commitments,
            &[multivariate_challenge.clone()],
            &evals,
            &mut kzg_transcript,
        )
        .unwrap();

        let proof = kzg_transcript.into_proof();
        let input_values = evals.iter().map(|eval| *eval.value()).collect::<Vec<Fp>>();

        Ok(KZGProof {
            proof,
            input_values,
            challenge: Some(multivariate_challenge),
        })
    }
}
