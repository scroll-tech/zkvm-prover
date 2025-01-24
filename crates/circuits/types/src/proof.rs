#[derive(
    Clone,
    Debug,
    rkyv::Deserialize,
    rkyv::Serialize,
    rkyv::Archive,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct FlattenedRootProof {
    pub flatten_proof: Vec<u32>,
    pub public_values: Vec<u32>,
}
