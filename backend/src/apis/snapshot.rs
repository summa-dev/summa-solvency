use std::path::Path;

use ethers::types::{Bytes, U256};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{ProvingKey, VerifyingKey},
    poly::kzg::commitment::ParamsKZG,
};
use snark_verifier_sdk::{evm::gen_evm_verifier_shplonk, CircuitExt};

use summa_solvency::{
    circuits::{
        merkle_sum_tree::MstInclusionCircuit,
        solvency::SolvencyCircuit,
        utils::{
            full_prover, gen_proof_solidity_calldata, generate_setup_artifacts,
            write_verifier_sol_from_yul,
        },
    },
    merkle_sum_tree::MerkleSumTree,
};

use crate::apis::csv_parser::parse_signature_csv;

pub struct Snapshot<const LEVELS: usize, const N_ASSETS: usize> {
    mst: MerkleSumTree<N_ASSETS>,
    proof_of_account_ownership: AccountOwnershipProof,
    trusted_setup: [SetupArtifcats; 2], // the first trusted setup relates to MstInclusionCircuit, the second related to SolvencyCircuit
}

pub(crate) type SetupArtifcats = (
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

#[derive(Debug, Clone)]
pub struct AccountOwnershipProof {
    addresses: Vec<String>,
    signatures: Vec<String>,
    message: String,
}

impl AccountOwnershipProof {
    pub fn get_addresses(&self) -> &Vec<String> {
        &self.addresses
    }

    pub fn get_signatures(&self) -> &Vec<String> {
        &self.signatures
    }

    pub fn get_message(&self) -> &String {
        &self.message
    }
}

impl<const LEVELS: usize, const N_ASSETS: usize> Snapshot<LEVELS, N_ASSETS>
where
    [usize; N_ASSETS + 1]: Sized,
    [usize; 2 * (1 + N_ASSETS)]: Sized,
{
    pub fn new(
        entry_csv_path: &str,
        signature_csv_path: &str,
        message: String,
        params_path: &str,
    ) -> Result<Snapshot<LEVELS, N_ASSETS>, Box<dyn std::error::Error>> {
        let (addresses, signatures) = parse_signature_csv(signature_csv_path).unwrap();

        let mst: MerkleSumTree<N_ASSETS> = MerkleSumTree::<N_ASSETS>::new(entry_csv_path).unwrap();

        let mst_inclusion_circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init_empty();
        let solvency_circuit = SolvencyCircuit::<N_ASSETS>::init_empty();

        // get k from ptau file name
        let parts: Vec<&str> = params_path.split("-").collect();
        let last_part = parts.last().unwrap();
        let k = last_part.parse::<u32>().unwrap();

        let mst_inclusion_setup_artifacts: SetupArtifcats =
            generate_setup_artifacts(k, Some(params_path), mst_inclusion_circuit).unwrap();

        let solvency_setup_artifacts_artifacts =
            generate_setup_artifacts(10, Some(params_path), solvency_circuit).unwrap();

        let trusted_setup = [
            mst_inclusion_setup_artifacts,
            solvency_setup_artifacts_artifacts,
        ];

        let proof_of_account_ownership = AccountOwnershipProof {
            addresses,
            signatures,
            message,
        };

        Ok(Snapshot {
            mst,
            proof_of_account_ownership,
            trusted_setup,
        })
    }

    // For generating onchain verifier contract
    pub fn generate_solvency_verifier(
        &self,
        yul_output_path: &str,
        sol_output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _deployment_code = gen_evm_verifier_shplonk::<SolvencyCircuit<N_ASSETS>>(
            &self.trusted_setup[1].0,
            &self.trusted_setup[1].2,
            vec![1 + N_ASSETS],
            Some(Path::new(yul_output_path)),
        );

        write_verifier_sol_from_yul(yul_output_path, sol_output_path).unwrap();

        Ok(())
    }

    pub fn generate_proof_of_solvency(
        &self,
        asset_contract_addresses: Vec<String>,
        asset_sums: [Fp; N_ASSETS],
    ) -> Result<(SolvencyProof, Vec<String>), &'static str> {
        let circuit = SolvencyCircuit::<N_ASSETS>::init(self.mst.clone(), asset_sums);

        let calldata = gen_proof_solidity_calldata(
            &self.trusted_setup[1].0,
            &self.trusted_setup[1].1,
            circuit,
        );

        Ok((
            SolvencyProof {
                proof_calldata: calldata.0,
                public_inputs: calldata.1,
            },
            asset_contract_addresses,
        ))
    }

    pub fn generate_proof_of_inclusion(
        &self,
        user_index: usize,
    ) -> Result<MstInclusionProof, &'static str> {
        let circuit = MstInclusionCircuit::<LEVELS, N_ASSETS>::init(self.mst.clone(), user_index);

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

    pub fn get_proof_of_account_ownership(&self) -> &AccountOwnershipProof {
        &self.proof_of_account_ownership
    }

    pub fn get_trusted_setup_for_mst_inclusion(&self) -> &SetupArtifcats {
        &self.trusted_setup[0]
    }

    pub fn get_trusted_setup_for_solvency(&self) -> &SetupArtifcats {
        &self.trusted_setup[1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const N_ASSETS: usize = 2;
    const LEVELS: usize = 4;

    fn initialize_snapshot() -> Snapshot<LEVELS, N_ASSETS> {
        let entry_csv = "../zk_prover/src/merkle_sum_tree/csv/entry_16.csv";
        let signature_csv = "src/apis/csv/signatures.csv";

        Snapshot::<LEVELS, N_ASSETS>::new(
            entry_csv,
            signature_csv,
            "Summa proof of solvency for CryptoExchange".to_string(),
            "ptau/hermez-raw-11",
        )
        .unwrap()
    }

    #[test]
    fn test_generate_solvency_verifier() {
        let snapshot = initialize_snapshot();

        let yul_output_path = "artifacts/test_verifier.yul";
        let sol_output_path = "artifacts/test_verifier.sol";

        snapshot
            .generate_solvency_verifier(yul_output_path, sol_output_path)
            .unwrap();

        let yul_meta = std::fs::metadata(yul_output_path);
        let sol_meta = std::fs::metadata(sol_output_path);
        assert!(yul_meta.is_ok());
        assert!(sol_meta.is_ok());

        std::fs::remove_file(yul_output_path).expect("Failed to remove Yul output file");
        std::fs::remove_file(sol_output_path).expect("Failed to remove Sol output file");
    }

    #[test]
    fn test_generate_solvency_proof() {
        let snapshot = initialize_snapshot();

        let asset_addresses: Vec<String> = vec![
            "0xe65267e87ed6fff28ff0d6edc39865d1d66274f5".to_string(), // ERC20 token address
            "0x220b71671b649c03714da9c621285943f3cbcdc6".to_string(), // ERC20 token address
        ];

        // In this test, we assume that the balances of the accounts in the snapshot are 556863 for both assets
        // In a live environment, Should fetch balances from on-chain via `fetch_asset_sums` method in `fetch.rs`.
        let calldata: (SolvencyProof, Vec<String>) = snapshot
            .generate_proof_of_solvency(
                asset_addresses.clone(),
                [Fp::from(556863), Fp::from(556863)],
            )
            .unwrap();

        assert_eq!(calldata.0.public_inputs.len(), 1 + N_ASSETS);
        assert_eq!(calldata.1.len(), asset_addresses.len());
    }

    #[test]
    fn test_generate_inclusion_proof() {
        let snapshot = initialize_snapshot();

        let inclusion_proof = snapshot.generate_proof_of_inclusion(0).unwrap();
        let public_inputs = inclusion_proof.get_public_inputs();

        assert_eq!(public_inputs.len(), 1); // 1 instance
        assert_eq!(public_inputs[0].len(), 2); // 2 values
    }

    #[test]
    fn test_get_proof_of_account_ownership() {
        let snapshot = initialize_snapshot();

        let proof_of_account_ownership = snapshot.get_proof_of_account_ownership();

        assert_eq!(proof_of_account_ownership.addresses.len(), 3);
        assert_eq!(proof_of_account_ownership.signatures.len(), 3);
        assert_eq!(
            proof_of_account_ownership.message,
            "Summa proof of solvency for CryptoExchange".to_string()
        );
    }
}
