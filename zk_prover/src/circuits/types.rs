use ethers::types::U256;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProofSolidityCallData {
    pub proof: String,
    pub public_inputs: Vec<U256>,
}

#[derive(Serialize, Deserialize)]
pub struct CommitmentSolidityCallData {
    pub root_hash: U256,
    pub root_balances: Vec<U256>,
}
