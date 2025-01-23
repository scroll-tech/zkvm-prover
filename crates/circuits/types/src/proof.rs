#[derive(serde::Deserialize, serde::Serialize)]
pub struct FlattenRootProof {
    pub flatten_proof: Vec<u32>,
    pub public_values: Vec<u32>,
}
