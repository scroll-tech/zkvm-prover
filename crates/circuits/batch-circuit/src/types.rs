use crate::ChunkInfo;
use rkyv::{Deserialize, Serialize, Archive};
use alloy_primitives::B256 as H256;
//mod prover;

//pub use prover::{MAX_AGG_CHUNKS, BatchProvingTask, ChunkKind, ChunkProofV2};

pub const MAX_AGG_CHUNKS: usize = 45;

/// Batch header provides additional fields from the context (within recursion)
/// for constructing the preimage of the batch hash.
/// A BatchHash from Batch header v3 consists of 2 hashes.
/// - batchHash := keccak256(version || batch_index || l1_message_popped || total_l1_message_popped ||
///   batch_data_hash || versioned_hash || parent_batch_hash || last_block_timestamp || z || y)
/// - batch_data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
#[derive(Default, Debug, Clone, Copy, Serialize, Deserialize, Archive, serde::Serialize, serde::Deserialize)]
#[rkyv(derive(Debug))]
pub struct BatchHeaderV3 {
    /// the batch version
    #[rkyv()]
    pub version: u8,
    /// the index of the batch
    #[rkyv()]
    pub batch_index: u64,
    /// Number of L1 messages popped in the batch
    #[rkyv()]
    pub l1_message_popped: u64,
    /// Number of total L1 messages popped after the batch
    #[rkyv()]
    pub total_l1_message_popped: u64,
    /// The parent batch hash
    #[rkyv()]
    pub parent_batch_hash: H256,
    /// The timestamp of the last block in this batch
    #[rkyv()]
    pub last_block_timestamp: u64,
    /// The data hash of the batch
    #[rkyv()]
    pub data_hash: H256,
    /// The versioned hash of the blob with this batch's data
    #[rkyv()]
    pub blob_versioned_hash: H256,
    /// The blob data proof: z (32), y (32)
    pub blob_data_proof: [H256; 2],
}

#[derive(Debug, Clone, Serialize, Deserialize, Archive)]
#[rkyv(derive(Debug))]
pub struct BatchTask {
    /// chunk infos
    #[rkyv()]
    pub chunks_info: Vec<ChunkInfo>,
    /// blob bytes
    #[rkyv()]
    pub blob_bytes: Vec<u8>,
    /// header of v3
    #[rkyv()]
    pub header_v3: Option<BatchHeaderV3>,
  
}