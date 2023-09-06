use ethers::{
    abi::Address,
    types::{Bytes, U256},
};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
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
        summasc_address: Address,
    ) -> Result<Round<LEVELS, N_ASSETS, N_BYTES>, Box<dyn Error>> {
        Ok(Round {
            snapshot: None,
            signer: SummaSigner::new(&vec![], signer_key, chain_id, rpc_url, summasc_address),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ethers::{
        core::k256::ecdsa::SigningKey,
        signers::{LocalWallet, Wallet},
        types::H160,
        utils::{Anvil, AnvilInstance},
    };
    use halo2_proofs::halo2curves::ff::PrimeField;
    use std::{str::from_utf8, str::FromStr, sync::Arc};

    use crate::contracts::{
        generated::{
            inclusion_verifier::InclusionVerifier, solvency_verifier::SolvencyVerifier,
            summa_contract::Summa,
        },
        tests::initialize_anvil,
    };

    const LEVELS: usize = 4;
    const N_ASSETS: usize = 2;
    const N_BYTES: usize = 14;

    #[tokio::test]
    async fn test_round_features() {
        let (anvil, cex_addr_1, cex_addr_2, client, _mock_erc20) = initialize_anvil().await;

        let solvency_verifer_contract = SolvencyVerifier::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let inclusion_verifer_contract = InclusionVerifier::deploy(Arc::clone(&client), ())
            .unwrap()
            .send()
            .await
            .unwrap();

        let summa_contract = Summa::deploy(
            Arc::clone(&client),
            (
                solvency_verifer_contract.address(),
                inclusion_verifer_contract.address(),
            ),
        )
        .unwrap()
        .send()
        .await
        .unwrap();

        // Initialize round
        let mut round = Round::<LEVELS, N_ASSETS, N_BYTES>::new(
            "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", // anvil account [0]
            anvil.chain_id(),
            anvil.endpoint().as_str(),
            summa_contract.address(),
        )
        .unwrap();

        let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
        let params_path = "ptau/hermez-raw-11";

        let assets = [
            Asset {
                asset_name: "ETH".to_string(),
                chain: "ETH".to_string(),
                amount: U256::from(556863),
            },
            Asset {
                asset_name: "USDT".to_string(),
                chain: "ETH".to_string(),
                amount: U256::from(556863),
            },
        ];

        // Build snapshot
        round.build_snapshot(entry_csv, params_path, 1);

        // Verify solvency proof
        let mut logs = summa_contract
            .solvency_proof_submitted_filter()
            .query()
            .await
            .unwrap();
        assert_eq!(logs.len(), 0);

        assert_eq!(round.dispatch_solvency_proof(assets).await.unwrap(), ());

        // after send transaction to submit proof of solvency, logs should be updated
        let mut logs = summa_contract
            .solvency_proof_submitted_filter()
            .query()
            .await
            .unwrap();

        assert_eq!(logs.len(), 1);

        // Test inclusion proof generation
        let inclusion_proof = round.get_proof_of_inclusion(0).unwrap();

        assert_eq!(
            inclusion_proof.public_inputs[0][0],
            Fp::from_str_vartime(
                "6362822108736413915574850018842190920390136280184018644072260166743334495239"
            )
            .unwrap()
        );
        assert_eq!(
            inclusion_proof.public_inputs[0][1],
            Fp::from_str_vartime(
                "1300633067792667740851197998552728163078912135282962223512949070409098715333"
            )
            .unwrap()
        );
    }
}
