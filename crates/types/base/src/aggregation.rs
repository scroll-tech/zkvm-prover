/// Represents an openvm program commitments and public values.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AggregationInput {
    /// Public values.
    pub public_values: Vec<u32>,
    /// Represent the commitment needed to verify a root proof
    pub commitment: ProgramCommitment,
}

/// Represent the commitment needed to verify a [`RootProof`].
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct ProgramCommitment {
    /// The commitment to the child program exe.
    pub exe: [u32; 8],
    /// The commitment to the child program vm.
    pub vm: [u32; 8],
}

/// Number of public-input values, i.e. [u32; N].
///
/// Note that the actual value for each u32 is a byte.
pub const NUM_PUBLIC_VALUES: usize = 32;

/// Witness for an [`AggregationCircuit`][AggCircuit] that also carries proofs that are being
/// aggregated.
pub trait ProofCarryingWitness {
    /// Get the root proofs from the witness.
    fn get_proofs(&self) -> Vec<AggregationInput>;
}
