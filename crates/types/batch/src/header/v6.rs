use super::BatchHeader;
use alloy_primitives::B256;
use types_base::utils::keccak256;

/// Represents the header summarising the batch of chunks as per DA-codec v6.
#[derive(Clone, Copy, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct BatchHeaderV6 {
    /// The DA-codec version for the batch.
    pub version: u8,
    /// The index of the batch
    pub batch_index: u64,
    /// Number of L1 messages popped in the batch
    pub l1_message_popped: u64,
    /// Number of total L1 messages popped after the batch
    pub total_l1_message_popped: u64,
    /// The parent batch hash
    pub parent_batch_hash: B256,
    /// The timestamp of the last block in this batch
    pub last_block_timestamp: u64,
    /// The data hash of the batch
    pub data_hash: B256,
    /// The versioned hash of the blob with this batch's data
    pub blob_versioned_hash: B256,
    /// The blob data proof: z (32), y (32)
    pub blob_data_proof: [B256; 2],
}

impl BatchHeader for BatchHeaderV6 {
    fn version(&self) -> u8 {
        self.version
    }

    fn index(&self) -> u64 {
        self.batch_index
    }

    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }

    /// Batch hash as per DA-codec v6:
    ///
    /// keccak(
    ///     version ||
    ///     batch index ||
    ///     l1 message popped ||
    ///     total l1 message popped ||
    ///     batch data hash ||
    ///     versioned hash ||
    ///     parent batch hash ||
    ///     last block timestamp ||
    ///     z ||
    ///     y
    /// )
    fn batch_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(vec![self.version].as_slice())
                .chain(self.batch_index.to_be_bytes().as_slice())
                .chain(self.l1_message_popped.to_be_bytes().as_slice())
                .chain(self.total_l1_message_popped.to_be_bytes().as_slice())
                .chain(self.data_hash.as_slice())
                .chain(self.blob_versioned_hash.as_slice())
                .chain(self.parent_batch_hash.as_slice())
                .chain(self.last_block_timestamp.to_be_bytes().as_slice())
                .chain(self.blob_data_proof[0].as_slice())
                .chain(self.blob_data_proof[1].as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    fn blob_versioned_hash(&self) -> B256 {
        self.blob_versioned_hash
    }
}
