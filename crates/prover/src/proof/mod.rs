use std::path::Path;

use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::verifier::root::types::RootVmVerifierInput;
use sbv::primitives::B256;
use scroll_zkvm_circuit_input_types::{batch::BatchInfo, bundle::BundleInfo, chunk::ChunkInfo};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::{
    Error, SC,
    utils::{base64, short_git_version},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WrappedProof<Metadata, Proof> {
    pub metadata: Metadata,
    pub proof: Proof,
    /// The content which can be used for distinguishing which vk
    /// the proof comes from. For RootProof it is commonly the
    /// hash of vm's program while for  EvmProof it is the
    /// raw bytes of the [`VerifyingKey`] of the [`Circuit`]
    /// used to generate the [`Snark`].
    #[serde(with = "base64")]
    pub vk: Vec<u8>,
    pub git_version: String,
}

/// Alias for convenience.
pub type RootProof = RootVmVerifierInput<SC>;

pub type ChunkProof = WrappedProof<ChunkProofMetadata, RootProof>;
pub type BatchProof = WrappedProof<BatchProofMetadata, RootProof>;
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
    Proof: DeserializeOwned + Serialize,
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
