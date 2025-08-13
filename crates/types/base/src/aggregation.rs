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

/// Represent the verification key needed to verify a [`RootProof`].
/// This is separate from ProgramCommitment as they serve different purposes.
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
pub struct VerificationKey {
    /// The verification key data for the circuit
    pub vk_data: Vec<u8>,
}

impl VerificationKey {
    pub fn new(vk_data: Vec<u8>) -> Self {
        Self { vk_data }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.vk_data.clone()
    }

    pub fn deserialize(vk_bytes: &[u8]) -> Self {
        Self {
            vk_data: vk_bytes.to_vec(),
        }
    }
}

/// A strongly-typed verification key for STARK verification.
/// It explicitly contains the exe and vm commitments required by the verifier.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct StarkVerificationKey {
    pub exe: [u32; 8],
    pub vm: [u32; 8],
}

impl StarkVerificationKey {
    pub fn new(exe: [u32; 8], vm: [u32; 8]) -> Self {
        Self { exe, vm }
    }

    /// Serialize using bincode v2 for a stable wire format.
    pub fn to_bytes_bincode(&self) -> Vec<u8> {
        bincode::serialize(self).expect("bincode serialize StarkVerificationKey")
    }

    /// Deserialize using bincode v2.
    pub fn from_bytes_bincode(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::deserialize(bytes)
    }
}

impl From<ProgramCommitment> for StarkVerificationKey {
    fn from(pc: ProgramCommitment) -> Self {
        Self { exe: pc.exe, vm: pc.vm }
    }
}

impl From<StarkVerificationKey> for ProgramCommitment {
    fn from(vk: StarkVerificationKey) -> Self {
        Self { exe: vk.exe, vm: vk.vm }
    }
}

impl ProgramCommitment {
    pub fn deserialize(commitment_bytes: &[u8]) -> Self {
        // TODO: temporary skip deserialize if no vk is provided
        if commitment_bytes.is_empty() {
            return Default::default();
        }

        let archived_data =
            rkyv::access::<ArchivedProgramCommitment, rkyv::rancor::BoxedError>(commitment_bytes)
                .unwrap();

        Self {
            exe: archived_data.exe.map(|u32_le| u32_le.to_native()),
            vm: archived_data.vm.map(|u32_le| u32_le.to_native()),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        rkyv::to_bytes::<rkyv::rancor::BoxedError>(self)
            .map(|v| v.to_vec())
            .unwrap()
    }
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
