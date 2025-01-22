use crate::{ChunkInfo, BatchHeader, AsLastBatchHeader, PIBuilder, types::BatchHeaderV3};
use crate::utils::base64;
use serde::{Deserialize, Serialize};
use alloy_primitives::{Address, BlockNumber, Bloom, Bytes, B256 as H256, B64, U256};

pub const MAX_AGG_CHUNKS: usize = 45;

// we grap all definations from zkevm-circuit to parse the json of batch task

/// The innermost SNARK belongs to the following variants.
#[derive(Copy, Clone, Debug, Deserialize, Serialize, PartialEq)]
pub enum ChunkKind {
    /// halo2-based SuperCircuit.
    Halo2,
    /// sp1-based STARK with a halo2-backend.
    Sp1,
}

impl Default for ChunkKind {
    fn default() -> Self {
        Self::Halo2
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofV2Metadata {
    /// The [`Protocol`][snark_verifier::Protocol] for the SNARK construction for the chunk proof.
    #[serde(with = "base64")]
    pub protocol: Vec<u8>,
    /// The chunk proof can be for either the halo2 or sp1 routes.
    #[serde(default)]
    pub chunk_kind: ChunkKind,
    /// The EVM execution traces as a result of executing all txs in the chunk.
    pub chunk_info: ChunkInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofV2 {
    /// The inner data that differs between chunk proofs, batch proofs and bundle proofs.
    #[serde(flatten)]
    pub inner: ChunkProofV2Metadata,
    /// The raw bytes of the proof in the [`Snark`].
    ///
    /// Serialized using base64 format in order to not bloat the JSON-encoded proof dump.
    #[serde(with = "base64")]
    pub proof: Vec<u8>,
    /// The public values, aka instances of this [`Snark`].
    #[serde(with = "base64")]
    pub instances: Vec<u8>,
    /// The raw bytes of the [`VerifyingKey`] of the [`Circuit`] used to generate the [`Snark`].
    #[serde(with = "base64")]
    pub vk: Vec<u8>,
    /// The git ref of the codebase.
    ///
    /// Generally useful for debug reasons to know the exact commit using which this proof was
    /// generated.
    pub git_version: String,
}


/// Defines a proving task for batch proof generation.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BatchProvingTask {
    /// Chunk proofs for the contiguous list of chunks within the batch.
    pub chunk_proofs: Vec<ChunkProofV2>,
    /// The [`BatchHeader`], as computed on-chain for this batch.
    ///
    /// Ref: https://github.com/scroll-tech/scroll-contracts/blob/2ac4f3f7e090d7127db4b13b3627cb3ce2d762bc/src/libraries/codec/BatchHeaderV3Codec.sol
    pub batch_header: BatchHeaderV3,
    /// The bytes encoding the batch data that will finally be published on-chain in the form of an
    /// EIP-4844 blob.
    #[serde(with = "base64")]
    pub blob_bytes: Vec<u8>,
}
