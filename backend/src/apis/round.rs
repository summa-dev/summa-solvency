use ethers::{
    abi::Address,
    types::{Bytes, U256},
};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
use serde_json::to_string_pretty;
use snark_verifier_sdk::CircuitExt;
use std::error::Error;

use crate::contracts::{generated::summa_contract::summa::Asset, signer::SummaSigner};
use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{full_prover, gen_proof_solidity_calldata, generate_setup_artifacts},
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

#[derive(Debug, Clone)]
pub struct MstInclusionProof {
    public_inputs: Vec<Vec<Fp>>,
    proof: Vec<u8>,
}

impl MstInclusionProof {
    pub fn get_public_inputs(&self) -> &Vec<Vec<Fp>> {
        &self.public_inputs
    }

    pub fn get_proof(&self) -> &Vec<u8> {
        &self.proof
    }
}

pub struct Snapshot<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> {
    mst: MerkleSumTree<N_ASSETS, N_BYTES>,
    timestamp: usize,
    trusted_setup: [SetupArtifacts; 2],
}

pub struct Round<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize> {
    snapshot: Option<Snapshot<LEVELS, N_ASSETS, N_BYTES>>,
    signer: SummaSigner,
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    Round<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub fn new(
        signer_key: &str,
        chain_id: u64,
        rpc_url: &str,
        summa_sc_address: Address,
    ) -> Result<Round<LEVELS, N_ASSETS, N_BYTES>, Box<dyn Error>> {
        Ok(Round {
            snapshot: None,
            signer: SummaSigner::new(&vec![], signer_key, chain_id, rpc_url, summa_sc_address),
        })
    }

    pub fn build_snapshot(&mut self, entry_csv_path: &str, params_path: &str, timestamp: usize) {
        let snapshot =
            Snapshot::<LEVELS, N_ASSETS, N_BYTES>::new(entry_csv_path, params_path, timestamp)
                .unwrap();
        self.snapshot = Some(snapshot);
    }

    pub async fn dispatch_solvency_proof(
        &mut self,
        assets: [Asset; N_ASSETS],
    ) -> Result<(), &'static str> {
        if self.snapshot.is_none() {
            return Err("snapshot is not built yet");
        }
        let snapshot = self.snapshot.as_ref().unwrap();

        // Convert U256 to Fp for generating proof of solvency
        let asset_sum: [Fp; N_ASSETS] = assets
            .iter()
            .map(|asset| Fp::from_raw(asset.amount.0) as Fp)
            .collect::<Vec<Fp>>()
            .try_into()
            .unwrap();

        let proof: SolvencyProof = match snapshot.generate_proof_of_solvency(asset_sum) {
            Ok(p) => p,
            Err(_) => return Err("Failed to generate proof of solvency"),
        };

        let result = self
            .signer
            .submit_proof_of_solvency(
                proof.public_inputs[0],
                assets.to_vec(),
                proof.proof_calldata,
                U256::from(snapshot.get_timestamp()),
            )
            .await;

        Ok(result.unwrap())
    }

    pub fn get_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<MstInclusionProof, &'static str> {
        let snapshot = self.snapshot.as_ref().unwrap();
        if snapshot.mst.entries().len() < user_index {
            return Err("user_index is out of range");
        }

        Ok(snapshot.generate_proof_of_inclusion(user_index).unwrap())
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize, const N_BYTES: usize>
    Snapshot<LEVELS, N_ASSETS, N_BYTES>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub fn new(
        entry_csv_path: &str,
        params_path: &str,
        timestamp: usize,
    ) -> Result<Snapshot<LEVELS, N_ASSETS, N_BYTES>, Box<dyn std::error::Error>> {
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
            timestamp,
            trusted_setup,
        })
    }

    pub fn get_timestamp(&self) -> usize {
        self.timestamp
    }

    pub fn generate_proof_of_solvency(
        &self,
        asset_sums: [Fp; N_ASSETS],
    ) -> Result<SolvencyProof, &'static str> {
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

        let proof = full_prover(
            &self.trusted_setup[0].0,
            &self.trusted_setup[0].1,
            circuit.clone(),
            circuit.instances(),
        );

        Ok(MstInclusionProof {
            public_inputs: circuit.instances(),
            proof,
        })
    }
}
