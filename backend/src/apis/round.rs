use ethers::types::{Bytes, U256};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
use serde::{Deserialize, Serialize};
use std::error::Error;

use crate::contracts::{generated::summa_contract::summa::Cryptocurrency, signer::SummaSigner};
use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        utils::{gen_proof_solidity_calldata, generate_setup_artifacts},
    },
    merkle_sum_tree::Tree,
};

pub(crate) type SetupArtifacts = (
    ParamsKZG<Bn256>,
    ProvingKey<G1Affine>,
    VerifyingKey<G1Affine>,
);

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

pub struct Snapshot<const LEVELS: usize, const N_CURRENCIES: usize, const N_BYTES: usize> {
    pub mst: Box<dyn Tree<N_CURRENCIES, N_BYTES>>,
    trusted_setup: SetupArtifacts,
}

pub struct Round<'a, const LEVELS: usize, const N_CURRENCIES: usize, const N_BYTES: usize> {
    timestamp: u64,
    snapshot: Snapshot<LEVELS, N_CURRENCIES, N_BYTES>,
    signer: &'a SummaSigner,
}

impl<const LEVELS: usize, const N_CURRENCIES: usize, const N_BYTES: usize>
    Round<'_, LEVELS, N_CURRENCIES, N_BYTES>
where
    [usize; N_CURRENCIES + 1]: Sized,
    [usize; N_CURRENCIES + 2]: Sized,
{
    pub fn new<'a>(
        signer: &'a SummaSigner,
        mst: Box<dyn Tree<N_CURRENCIES, N_BYTES>>,
        params_path: &str,
        timestamp: u64,
    ) -> Result<Round<'a, LEVELS, N_CURRENCIES, N_BYTES>, Box<dyn Error>>
    where
        [(); N_CURRENCIES + 2]: Sized,
    {
        Ok(Round {
            timestamp,
            snapshot: Snapshot::<LEVELS, N_CURRENCIES, N_BYTES>::new(mst, params_path).unwrap(),
            signer: &signer,
        })
    }

    pub fn get_timestamp(&self) -> u64 {
        self.timestamp
    }

    pub async fn dispatch_commitment(&mut self) -> Result<(), Box<dyn Error>> {
        let root_str = format!("{:?}", self.snapshot.mst.root().hash);
        let mst_root = U256::from_str_radix(&root_str, 16).unwrap();

        let mut root_sums = Vec::<U256>::new();

        for balance in self.snapshot.mst.root().balances.iter() {
            let fp_str = format!("{:?}", balance);
            root_sums.push(U256::from_str_radix(&fp_str, 16).unwrap());
        }

        self.signer
            .submit_commitment(
                mst_root,
                root_sums,
                self.snapshot
                    .mst
                    .cryptocurrencies()
                    .iter()
                    .map(|cryptocurrency| Cryptocurrency {
                        name: cryptocurrency.name.clone(),
                        chain: cryptocurrency.chain.clone(),
                    })
                    .collect::<Vec<Cryptocurrency>>()
                    .as_slice()
                    .try_into()
                    .unwrap(),
                U256::from(self.get_timestamp()),
            )
            .await?;

        Ok(())
    }

    pub fn get_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<MstInclusionProof, &'static str>
    where
        [(); N_CURRENCIES + 2]: Sized,
    {
        Ok(self
            .snapshot
            .generate_proof_of_inclusion(user_index)
            .unwrap())
    }
}

impl<const LEVELS: usize, const N_CURRENCIES: usize, const N_BYTES: usize>
    Snapshot<LEVELS, N_CURRENCIES, N_BYTES>
where
    [usize; N_CURRENCIES + 1]: Sized,
    [usize; N_CURRENCIES + 2]: Sized,
{
    pub fn new(
        mst: Box<dyn Tree<N_CURRENCIES, N_BYTES>>,
        params_path: &str,
    ) -> Result<Snapshot<LEVELS, N_CURRENCIES, N_BYTES>, Box<dyn std::error::Error>> {
        let mst_inclusion_circuit =
            MstInclusionCircuit::<LEVELS, N_CURRENCIES, N_BYTES>::init_empty();

        // get k from ptau file name
        let parts: Vec<&str> = params_path.split("-").collect();
        let last_part = parts.last().unwrap();
        let k = last_part.parse::<u32>().unwrap();

        let mst_inclusion_setup_artifacts: SetupArtifacts =
            generate_setup_artifacts(k, Some(params_path), mst_inclusion_circuit).unwrap();

        Ok(Snapshot {
            mst,
            trusted_setup: mst_inclusion_setup_artifacts,
        })
    }

    pub fn generate_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<MstInclusionProof, &'static str>
    where
        [(); N_CURRENCIES + 2]: Sized,
    {
        let merkle_proof = self.mst.generate_proof(user_index).unwrap();
        let circuit = MstInclusionCircuit::<LEVELS, N_CURRENCIES, N_BYTES>::init(merkle_proof);

        // Currently, default manner of generating a inclusion proof for solidity-verifier.
        let calldata = gen_proof_solidity_calldata(
            &self.trusted_setup.0,
            &self.trusted_setup.1,
            circuit.clone(),
        );

        Ok(MstInclusionProof {
            proof_calldata: calldata.0,
            public_inputs: calldata.1,
        })
    }
}
