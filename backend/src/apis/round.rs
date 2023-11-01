use ethers::types::{Bytes, U256};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
use serde::{Deserialize, Serialize};
use std::error::Error;

use super::csv_parser::parse_asset_csv;
use crate::contracts::{generated::summa_contract::summa::Asset, signer::SummaSigner};
use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{gen_proof_solidity_calldata, generate_setup_artifacts},
    },
    merkle_sum_tree::MerkleSumTree,
};

pub(crate) type SetupArtifacts = (
    ParamsKZG<Bn256>,
    ProvingKey<G1Affine>,
    VerifyingKey<G1Affine>,
);

#[derive(Debug, Clone)]
pub struct SolvencyProof {
    public_inputs: Vec<U256>,
    proof_calldata: Bytes,
}

impl SolvencyProof {
    pub fn get_public_inputs(&self) -> &Vec<U256> {
        &self.public_inputs
    }

    pub fn get_proof_calldata(&self) -> &Bytes {
        &self.proof_calldata
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MstInclusionProof {
    public_inputs: Vec<U256>,
    proof_calldata: Bytes,
}

impl MstInclusionProof {
    pub fn get_public_inputs(&self) -> &Vec<U256> {
        &self.public_inputs
    }

    pub fn get_proof(&self) -> &Bytes {
        &self.proof_calldata
    }
}

pub struct Snapshot<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> {
    mst: MerkleSumTree<N_ASSETS, N_BYTES>,
    assets_state: [Asset; N_ASSETS],
    trusted_setup: [SetupArtifacts; 2],
}

pub struct Round<'a, const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> {
    timestamp: u64,
    snapshot: Snapshot<LEVELS, N_ASSETS, N_BYTES>,
    signer: &'a SummaSigner,
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    Round<'_, LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub fn new<'a>(
        signer: &'a SummaSigner,
        entry_csv_path: &str,
        asset_csv_path: &str,
        params_path: &str,
        timestamp: u64,
    ) -> Result<Round<'a, LEVELS, N_ASSETS, N_BYTES>, Box<dyn Error>> {
        Ok(Round {
            timestamp,
            snapshot: Snapshot::<LEVELS, N_ASSETS, N_BYTES>::new(
                asset_csv_path,
                entry_csv_path,
                params_path,
            )
            .unwrap(),
            signer: &signer,
        })
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    pub async fn dispatch_solvency_proof(&mut self) -> Result<(), Box<dyn Error>> {
        let proof: SolvencyProof = match self.snapshot.generate_proof_of_solvency() {
            Ok(p) => p,
            Err(e) => return Err(format!("Failed to generate proof of solvency: {}", e).into()),
        };

        self.signer
            .submit_proof_of_solvency(
                proof.public_inputs[0],
                self.snapshot.assets_state.to_vec(),
                proof.proof_calldata,
                U256::from(self.get_timestamp()),
            )
            .await?;

        Ok(())
    }

    pub fn get_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<MstInclusionProof, &'static str> {
        Ok(self
            .snapshot
            .generate_proof_of_inclusion(user_index)
            .unwrap())
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    Snapshot<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub fn new(
        asset_csv_path: &str,
        entry_csv_path: &str,
        params_path: &str,
    ) -> Result<Snapshot<LEVELS, N_ASSETS, N_BYTES>, Box<dyn std::error::Error>> {
        let assets_state = parse_asset_csv::<&str, N_ASSETS>(asset_csv_path).unwrap();
        let mst = MerkleSumTree::<N_ASSETS, N_BYTES>::new(entry_csv_path).unwrap();

        let mst_inclusion_circuit = MstInclusionCircuit::<LEVELS, N_ASSETS, N_BYTES>::init_empty();
        let solvency_circuit = SolvencyCircuit::<N_ASSETS, N_BYTES>::init_empty();

        // get k from ptau file name
        let parts: Vec<&str> = params_path.split("-").collect();
        let last_part = parts.last().unwrap();
        let k = last_part.parse::<u32>().unwrap();

        let mst_inclusion_setup_artifacts: SetupArtifacts =
            generate_setup_artifacts(k, Some(params_path), mst_inclusion_circuit).unwrap();

        let solvency_setup_artifacts_artifacts =
            generate_setup_artifacts(10, Some(params_path), solvency_circuit).unwrap();

        let trusted_setup = [
            mst_inclusion_setup_artifacts,
            solvency_setup_artifacts_artifacts,
        ];

        Ok(Snapshot {
            mst,
            assets_state,
            trusted_setup,
        })
    }

    pub fn generate_proof_of_solvency(&self) -> Result<SolvencyProof, &'static str> {
        let asset_sums = self
            .assets_state
            .iter()
            .map(|asset| Fp::from_raw(asset.amount.0) as Fp)
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap();
        let circuit = SolvencyCircuit::<N_ASSETS, N_BYTES>::init(self.mst.clone(), asset_sums);

        let calldata = gen_proof_solidity_calldata(
            &self.trusted_setup[1].0,
            &self.trusted_setup[1].1,
            circuit,
        );

        Ok(SolvencyProof {
            proof_calldata: calldata.0,
            public_inputs: calldata.1,
        })
    }

    pub fn generate_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<MstInclusionProof, &'static str> {
        let circuit =
            MstInclusionCircuit::<LEVELS, N_ASSETS, N_BYTES>::init(self.mst.clone(), user_index);

        // Currently, default manner of generating a inclusion proof for solidity-verifier.
        let calldata = gen_proof_solidity_calldata(
            &self.trusted_setup[0].0,
            &self.trusted_setup[0].1,
            circuit.clone(),
        );

        Ok(MstInclusionProof {
            proof_calldata: calldata.0,
            public_inputs: calldata.1,
        })
    }
}
