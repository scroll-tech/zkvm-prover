use std::path::Path;

use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::verifier::root::types::RootVmVerifierInput;
use sbv::primitives::B256;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{Error, SC, utils::short_git_version};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedProof<Metadata, Proof> {
    pub metadata: Metadata,
    pub proof: Proof,
    pub git_version: String,
}

/// Alias for convenience.
pub type RootProof = RootVmVerifierInput<SC>;

pub type ChunkProof = WrappedProof<ChunkProofMetadata, RootProof>;
pub type BatchProof = WrappedProof<BatchProofMetadata, RootProof>;
pub type BundleProof = WrappedProof<BundleProofMetadata, EvmProof>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofMetadata {
    #[cfg(feature = "scroll")]
    pub chunk_info: sbv::core::ChunkInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchProofMetadata {
    pub batch_hash: B256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BundleProofMetadata;

impl<Metadata, Proof> WrappedProof<Metadata, Proof>
where
    Metadata: DeserializeOwned + Serialize,
    Proof: DeserializeOwned + Serialize,
{
    /// Wrap a proof with some metadata.
    pub fn new(metadata: Metadata, proof: Proof) -> Self {
        Self {
            metadata,
            proof,
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
