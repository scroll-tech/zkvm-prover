use alloy_primitives::B256;
use rkyv::{Archive, Deserialize, Serialize};

use crate::{
    ProofCarryingWitness, chunk::ChunkInfo, proof::RootProofWithPublicValues, utils::keccak256,
};

/// The upper bound for the number of chunks that can be aggregated in a single batch.
pub const MAX_AGG_CHUNKS: usize = 45;

/// Batch header provides additional fields from the context (within recursion)
/// for constructing the preimage of the batch hash.
///
/// A BatchHash from Batch header v3 consists of 2 hashes.
///
/// - batch_hash :=
///     keccak256(
///         version ||
///         batch_index ||
///         l1_message_popped ||
///         total_l1_message_popped ||
///         batch_data_hash ||
///         versioned_hash ||
///         parent_batch_hash ||
///         last_block_timestamp ||
///         z ||
///         y
///     )
///
/// - data_hash := keccak(chunk_0.data_hash || ... || chunk_k-1.data_hash)
#[derive(
    Default,
    Debug,
    Clone,
    Copy,
    Serialize,
    Deserialize,
    Archive,
    serde::Serialize,
    serde::Deserialize,
)]
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
    pub parent_batch_hash: B256,
    /// The timestamp of the last block in this batch
    #[rkyv()]
    pub last_block_timestamp: u64,
    /// The data hash of the batch
    #[rkyv()]
    pub data_hash: B256,
    /// The versioned hash of the blob with this batch's data
    #[rkyv()]
    pub blob_versioned_hash: B256,
    /// The blob data proof: z (32), y (32)
    pub blob_data_proof: [B256; 2],
}

/// Reference header indicate the version of batch header base on which batch hash
/// should be calculated.
#[derive(Debug, Clone, Serialize, Deserialize, Archive)]
#[rkyv(derive(Debug))]
pub enum ReferenceHeader {
    V3(BatchHeaderV3),
}

/// Witness input to the batch circuit.
#[derive(Debug, Clone, Serialize, Deserialize, Archive)]
#[rkyv(derive(Debug))]
pub struct BatchWitness {
    /// Flattened root proofs from all chunks in the batch.
    #[rkyv()]
    pub chunk_proofs: Vec<RootProofWithPublicValues>,
    /// chunk infos
    #[rkyv()]
    pub chunk_infos: Vec<ChunkInfo>,
    /// blob bytes
    #[rkyv()]
    pub blob_bytes: Vec<u8>,
    /// header for reference
    #[rkyv()]
    pub reference_header: ReferenceHeader,
}

impl ProofCarryingWitness for ArchivedBatchWitness {
    fn get_proofs(&self) -> Vec<RootProofWithPublicValues> {
        self.chunk_proofs
            .iter()
            .map(|archived| RootProofWithPublicValues {
                flattened_proof: archived
                    .flattened_proof
                    .iter()
                    .map(|u32_le| u32_le.to_native())
                    .collect(),
                public_values: archived
                    .public_values
                    .iter()
                    .map(|u32_le| u32_le.to_native())
                    .collect(),
            })
            .collect()
    }
}

pub trait BatchHeader {
    fn version(&self) -> u8;
    fn index(&self) -> u64;
    fn batch_hash(&self) -> B256;
}

impl BatchHeader for BatchHeaderV3 {
    fn version(&self) -> u8 {
        self.version
    }
    fn index(&self) -> u64 {
        self.batch_index
    }
    fn batch_hash(&self) -> B256 {
        // the current batch hash is build as
        // keccak256(
        //     version ||
        //     batch_index ||
        //     l1_message_popped ||
        //     total_l1_message_popped ||
        //     batch_data_hash ||
        //     versioned_hash ||
        //     parent_batch_hash ||
        //     last_block_timestamp ||
        //     z ||
        //     y
        // )
        let batch_hash_preimage = [
            vec![self.version].as_slice(),
            self.batch_index.to_be_bytes().as_ref(),
            self.l1_message_popped.to_be_bytes().as_ref(),
            self.total_l1_message_popped.to_be_bytes().as_ref(),
            self.data_hash.as_slice(),
            self.blob_versioned_hash.as_slice(),
            self.parent_batch_hash.as_slice(),
            self.last_block_timestamp.to_be_bytes().as_ref(),
            self.blob_data_proof[0].as_slice(),
            self.blob_data_proof[1].as_slice(),
        ]
        .concat();
        keccak256(batch_hash_preimage)
    }
}

impl BatchHeader for ArchivedBatchHeaderV3 {
    fn version(&self) -> u8 {
        self.version
    }
    fn index(&self) -> u64 {
        self.batch_index.into()
    }
    fn batch_hash(&self) -> B256 {
        let batch_index: u64 = self.batch_index.into();
        let l1_message_popped: u64 = self.l1_message_popped.into();
        let total_l1_message_popped: u64 = self.total_l1_message_popped.into();
        let data_hash: B256 = self.data_hash.into();
        let blob_versioned_hash: B256 = self.blob_versioned_hash.into();
        let parent_batch_hash: B256 = self.parent_batch_hash.into();
        let last_block_timestamp: u64 = self.last_block_timestamp.into();
        let blob_data_proof: [B256; 2] = self.blob_data_proof.map(|h| h.into());
        let batch_hash_preimage = [
            vec![self.version].as_slice(),
            batch_index.to_be_bytes().as_ref(),
            l1_message_popped.to_be_bytes().as_ref(),
            total_l1_message_popped.to_be_bytes().as_ref(),
            data_hash.as_slice(),
            blob_versioned_hash.as_slice(),
            parent_batch_hash.as_slice(),
            last_block_timestamp.to_be_bytes().as_ref(),
            blob_data_proof[0].as_slice(),
            blob_data_proof[1].as_slice(),
        ]
        .concat();
        keccak256(batch_hash_preimage)
    }
}

pub trait KnownLastBatchHash {
    fn parent_batch_hash(&self) -> B256;
}

impl KnownLastBatchHash for BatchHeaderV3 {
    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }
}

impl KnownLastBatchHash for ArchivedBatchHeaderV3 {
    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash.into()
    }
}

/// generic for batch header types which also contain information of its parent
pub struct AsLastBatchHeader<'a, T: KnownLastBatchHash + BatchHeader>(pub &'a T);

impl<T: KnownLastBatchHash + BatchHeader> BatchHeader for AsLastBatchHeader<'_, T> {
    fn batch_hash(&self) -> B256 {
        self.0.parent_batch_hash()
    }
    fn version(&self) -> u8 {
        self.0.version()
    }
    fn index(&self) -> u64 {
        self.0.index() - 1
    }
}
