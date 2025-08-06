use crate::utils::{as_base64, vec_as_base64};
use openvm_sdk::{
    SC,
    commit::{AppExecutionCommit, CommitBytes},
    types::ProofData,
};
use openvm_stark_sdk::{
    openvm_stark_backend::{p3_field::PrimeField32, proof::Proof},
    p3_baby_bear::BabyBear,
};
use serde::{Deserialize, Serialize};

/// Helper type for convenience that implements [`From`] and [`Into`] traits between
/// [`OpenVmEvmProof`]. The difference is that the instances in [`EvmProof`] are the byte-encoding
/// of the flattened [`Fr`] elements.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct EvmProof {
    /// The proof bytes.
    #[serde(with = "vec_as_base64")]
    pub proof: Vec<u8>,
    /// The accmulator bytes.
    #[serde(with = "vec_as_base64")]
    pub accumulator: Vec<u8>,
    /// The public inputs of the SNARK proof.
    /// Previously the `instance`s are U256 values, with accumulator and digests.
    /// For real user PI values, they will be like 0x0000..00000ab, only 1 byte non zero.
    /// Usually of length (12+2+32)x32
    /// Now: the `instance` is splitted. The `user_public_values` is "dense".
    /// Each byte is valid PI. Usually of length 32.
    #[serde(with = "vec_as_base64")]
    pub user_public_values: Vec<u8>,
    pub digest1: [u32; 8],
    pub digest2: [u32; 8],
}

/// Helper to modify serde implementations on the remote [`RootProof`] type.
#[derive(Clone, Serialize, Deserialize)]
pub struct StarkProof {
    /// The proofs.
    #[serde(with = "as_base64")]
    pub proof: Proof<SC>,
    /// The public values for the proof.
    #[serde(with = "as_base64")]
    pub user_public_values: Vec<BabyBear>,
    pub exe_commitment: [u32; 8],
    pub vm_commitment: [u32; 8],
}

pub use openvm_sdk::types::EvmProof as OpenVmEvmProof;

impl From<OpenVmEvmProof> for EvmProof {
    fn from(value: OpenVmEvmProof) -> Self {
        Self {
            proof: value.proof_data.proof,
            accumulator: value.proof_data.accumulator,
            user_public_values: value.user_public_values,
            digest1: value.app_commit.app_exe_commit.to_u32_digest(),
            digest2: value.app_commit.app_vm_commit.to_u32_digest(),
        }
    }
}

impl From<EvmProof> for OpenVmEvmProof {
    fn from(value: EvmProof) -> Self {
        Self {
            user_public_values: value.user_public_values,
            proof_data: ProofData {
                accumulator: value.accumulator,
                proof: value.proof,
            },
            app_commit: AppExecutionCommit {
                app_exe_commit: CommitBytes::from_u32_digest(&value.digest1),
                app_vm_commit: CommitBytes::from_u32_digest(&value.digest2),
            },
        }
    }
}

/// Lists the proof variants possible in Scroll's proving architecture.
#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ProofEnum {
    /// Represents a STARK proof used for intermediary layers, i.e. chunk and batch.
    Stark(StarkProof),
    /// Represents a SNARK proof used for the final layer to be verified on-chain, i.e. bundle.
    Evm(EvmProof),
}

impl From<StarkProof> for ProofEnum {
    fn from(value: StarkProof) -> Self {
        Self::Stark(value)
    }
}

impl From<EvmProof> for ProofEnum {
    fn from(value: EvmProof) -> Self {
        Self::Evm(value)
    }
}

impl ProofEnum {
    /// Get the stark proof as reference.
    pub fn as_stark_proof(&self) -> Option<&StarkProof> {
        match self {
            Self::Stark(proof) => Some(proof),
            _ => None,
        }
    }

    /// Get the EVM proof as defined in [`openvm_native_recursion`].
    ///
    /// Essentially construct a [`OpenVmEvmProof`] from the inner contained [`EvmProof`].
    pub fn as_evm_proof(&self) -> Option<&EvmProof> {
        match self {
            Self::Evm(proof) => Some(proof),
            _ => None,
        }
    }

    /// Consumes the proof enum and returns the contained root proof.
    pub fn into_stark_proof(self) -> Option<StarkProof> {
        match self {
            Self::Stark(proof) => Some(proof),
            _ => None,
        }
    }

    /// Consumes the proof enum and returns the [`OpenVmEvmProof`].
    pub fn into_evm_proof(self) -> Option<EvmProof> {
        match self {
            Self::Evm(proof) => Some(proof),
            _ => None,
        }
    }

    /// Extracts public input values from the proof.
    ///
    /// # Returns
    /// - For Stark proofs: A vector of u32 values converted from BabyBear field elements
    /// - For EVM proofs: A vector of u32 values, each containing a single byte from the original vector
    /// - The returned vector typically contains 32 elements, where each u32 represents a single byte value.
    ///
    /// Note: This method handles the different encoding formats between proof types.
    /// Each returned u32 typically only uses the lower 8 bits (one byte) of its capacity.
    pub fn public_values(&self) -> Vec<u32> {
        match self {
            Self::Stark(stark_proof) => stark_proof
                .user_public_values
                .iter()
                .map(|x| x.as_canonical_u32())
                .collect::<Vec<u32>>(),
            Self::Evm(evm_proof) => evm_proof
                .user_public_values
                .iter()
                .map(|byte| *byte as u32)
                .collect::<Vec<u32>>(),
        }
    }
}
