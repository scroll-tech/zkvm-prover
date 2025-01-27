/// Represents an openvm root proof with the proof and public values flattened.
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
pub struct RootProofWithPublicValues {
    /// Flattened proof bytes.
    pub flattened_proof: Vec<u32>,
    /// Flattened public values.
    pub public_values: Vec<u32>,
}
