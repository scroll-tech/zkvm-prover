use alloy_primitives::B256;

use super::BatchHeader;
use types_base::utils::keccak256;

/// Represents the header summarising the batch of chunks as per DA-codec v7.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct BatchHeaderV7 {
    /// The DA-codec version for the batch.
    #[rkyv()]
    pub version: u8,
    /// The index of the batch
    #[rkyv()]
    pub batch_index: u64,
    /// The parent batch hash
    #[rkyv()]
    pub parent_batch_hash: B256,
    /// The versioned hash of the blob with this batch's data
    #[rkyv()]
    pub blob_versioned_hash: B256,
}

impl BatchHeader for BatchHeaderV7 {
    fn version(&self) -> u8 {
        self.version
    }

    fn index(&self) -> u64 {
        self.batch_index
    }

    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }

    /// Batch hash as per DA-codec v7:
    ///
    /// keccak(
    ///     version ||
    ///     batch index ||
    ///     versioned hash ||
    ///     parent batch hash
    /// )
    fn batch_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(vec![self.version].as_slice())
                .chain(self.batch_index.to_be_bytes().as_slice())
                .chain(self.blob_versioned_hash.as_slice())
                .chain(self.parent_batch_hash.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    fn blob_versioned_hash(&self) -> B256 {
        self.blob_versioned_hash
    }
}

