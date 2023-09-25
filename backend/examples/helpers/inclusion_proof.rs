use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct InclusionProof {
    pub leaf_hash: String,
    pub root_hash: String,
    pub proof: String,
}
