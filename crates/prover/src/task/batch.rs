use scroll_zkvm_circuit_input_types::{
    batch::{BatchHeader, BatchHeaderV3, BatchWitness, ReferenceHeader},
    chunk::ChunkInfo,
};
use serde::{Deserialize, Serialize};

use crate::{ChunkProof, task::ProvingTask, utils::base64};

use super::chunk::ChunkProvingTask;

// we grap all definations from zkevm-circuit to parse the json of batch task

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofV2Metadata {
    pub chunk_info: ChunkInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChunkProofV2 {
    /// The inner data that differs between chunk proofs, batch proofs and bundle proofs.
    /// TODO: do we still need metadata? or simply the chunk info?
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
    /// The [`BatchHeaderV3`], as computed on-chain for this batch.
    ///
    /// Ref: https://github.com/scroll-tech/scroll-contracts/blob/2ac4f3f7e090d7127db4b13b3627cb3ce2d762bc/src/libraries/codec/BatchHeaderV3Codec.sol
    pub batch_header: BatchHeaderV3,
    /// The bytes encoding the batch data that will finally be published on-chain in the form of an
    /// EIP-4844 blob.
    #[serde(with = "base64")]
    pub blob_bytes: Vec<u8>,
}

impl BatchProvingTask {
    pub fn serialized_into(self) -> rkyv::util::AlignedVec {
        let input_task = BatchWitness {
            chunks_info: self
                .chunk_proofs
                .iter()
                .map(|chunk_proofs| chunk_proofs.inner.chunk_info.clone())
                .collect(),
            blob_bytes: self.blob_bytes,
            reference_header: ReferenceHeader::V3(self.batch_header),
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&input_task).unwrap()
    }
}

impl BatchProvingTask {
    /// Construct a new [`BatchProvingTask`] given the list of [`ChunkProvingTask`]s and their
    /// respective [`ChunkProof`]s.
    pub fn build(chunk_tasks: &[ChunkProvingTask], chunk_proofs: &[ChunkProof]) -> Self {
        // Sanity check.
        assert_eq!(chunk_tasks.len(), chunk_proofs.len());

        unimplemented!()
    }
}

impl ProvingTask for BatchProvingTask {
    fn identifier(&self) -> String {
        self.batch_header.batch_hash().to_string()
    }
}
