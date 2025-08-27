/// Represents an openvm program commitments and public values.
#[derive(
    Clone,
    Debug,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct AggregationInput {
    /// Public values.
    pub public_values: Vec<u32>,
    /// Represent the commitment needed to verify a root proof
    pub commitment: ProgramCommitment,
}

/// Represent the commitment needed to verify a [`RootProof`].
#[derive(
    Clone,
    Debug,
    Default,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct ProgramCommitment {
    /// The commitment to the child program exe.
    pub exe: [u32; 8],
    /// The commitment to the child program vm.
    pub vm: [u32; 8],
}

impl From<&ArchivedProgramCommitment> for ProgramCommitment {
    fn from(archived: &ArchivedProgramCommitment) -> Self {
        Self {
            exe: archived.exe.map(|u32_le| u32_le.to_native()),
            vm: archived.vm.map(|u32_le| u32_le.to_native()),
        }
    }
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
