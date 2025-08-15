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

impl ProgramCommitment {
    pub fn deserialize(commitment_bytes: &[u8]) -> Self {
        // TODO: temporary skip deserialize if no vk is provided
        assert_eq!(commitment_bytes.len(), 64);
        let mut exe: [u32; 8] = [0; 8];
        for (i, bytes4) in commitment_bytes[..32].chunks(4).enumerate() {
            let bytes: [u8; 4] = bytes4.try_into().unwrap();
            exe[i] = u32::from_le_bytes(bytes);
        }

        let mut vm: [u32; 8] = [0; 8];
        for (i, bytes4) in commitment_bytes[32..].chunks(4).enumerate() {
            let bytes: [u8; 4] = bytes4.try_into().unwrap();
            vm[i] = u32::from_le_bytes(bytes);
        }
        Self { exe, vm }
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.exe
            .iter()
            .chain(self.vm.iter())
            .flat_map(|u| u.to_le_bytes().into_iter())
            .collect()
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
