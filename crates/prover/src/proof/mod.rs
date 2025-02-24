use std::path::Path;

use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::verifier::root::types::RootVmVerifierInput;
use sbv::primitives::B256;
use scroll_zkvm_circuit_input_types::{batch::BatchInfo, bundle::BundleInfo, chunk::ChunkInfo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Error, SC, utils::short_git_version};

mod utils;
use utils::LegacyProofFormat;

/// A wrapper around the actual inner proof.
#[derive(Clone)]
pub struct WrappedProof<Metadata, Proof> {
    /// Generic metadata carried by a proof.
    pub metadata: Metadata,
    /// The inner proof, either a [`RootProof`] or [`EvmProof`] depending on the [`crate::ProverType`].
    pub proof: Proof,
    /// Represents the verifying key in serialized form. The purpose of including the verifying key
    /// along with the proof is to allow a verifier-only mode to identify the source of proof
    /// generation.
    ///
    /// For [`RootProof`] the verifying key is denoted by the digest of the VM's program.
    ///
    /// For [`EvmProof`] its the raw bytes of the halo2 circuit's `VerifyingKey`.
    ///
    /// We encode the vk in base64 format during JSON serialization.
    pub vk: Vec<u8>,
    /// Represents the git ref for `zkvm-prover` that was used to construct the proof.
    ///
    /// This is useful for debugging.
    pub git_version: String,
}

/// Alias for convenience.
pub type RootProof = RootVmVerifierInput<SC>;

/// Alias for convenience.
pub type ChunkProof = WrappedProof<ChunkProofMetadata, RootProof>;

/// Alias for convenience.
pub type BatchProof = WrappedProof<BatchProofMetadata, RootProof>;

/// Alias for convenience.
pub type BundleProof = WrappedProof<BundleProofMetadata, EvmProof>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofMetadata {
    pub chunk_info: ChunkInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchProofMetadata {
    pub batch_info: BatchInfo,
    pub batch_hash: B256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleProofMetadata {
    pub bundle_info: BundleInfo,
    pub bundle_pi_hash: B256,
}

impl<Metadata, Proof> WrappedProof<Metadata, Proof>
where
    Metadata: DeserializeOwned + Serialize,
    Proof: DeserializeOwned + Serialize + LegacyProofFormat,
{
    /// Wrap a proof with some metadata.
    pub fn new(metadata: Metadata, proof: Proof, vk: Option<&[u8]>) -> Self {
        Self {
            metadata,
            proof,
            vk: vk.map(Vec::from).unwrap_or_default(),
            git_version: short_git_version(),
        }
    }

    /// Read and deserialize the proof.
    pub fn from_json<P: AsRef<Path>>(path_proof: P) -> Result<Self, Error> {
        crate::utils::read_json_deep(path_proof)
    }

    /// Serialize the proof and dumping at the given path.
    pub fn dump<P: AsRef<Path>>(&self, path_proof: P) -> Result<(), Error> {
        crate::utils::write_json(path_proof, &self)
    }
}
