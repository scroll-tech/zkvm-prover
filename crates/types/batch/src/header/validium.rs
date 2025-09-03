use alloy_primitives::B256;
use types_base::utils::keccak256;

use super::{BatchHeader, ValidiumBatchHeader};

/// Batch header used in L3 validium.
#[derive(
    Clone,
    Copy,
    Debug,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub enum BatchHeaderValidium {
    /// L3 validium @ v1 batch header.
    V1(BatchHeaderValidiumV1),
}

/// Represents the batch header summarising a L3 validium batch.
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
pub struct BatchHeaderValidiumV1 {
    /// The DA-codec version for the batch.
    #[rkyv()]
    pub version: u8,
    /// The index of the batch
    #[rkyv()]
    pub batch_index: u64,
    /// The parent batch hash
    #[rkyv()]
    pub parent_batch_hash: B256,
    /// The state root after applying the batch.
    #[rkyv()]
    pub post_state_root: B256,
    /// The withdraw root post the batch.
    #[rkyv()]
    pub withdraw_root: B256,
    /// A commitment that binds the batch to its payload. It also serves provability based on the
    /// finalised L2 data.
    ///
    /// We utilise the last L3 block's blockhash as commitment.
    #[rkyv()]
    pub commitment: B256,
}

impl ValidiumBatchHeader for BatchHeaderValidium {
    fn commitment(&self) -> Vec<u8> {
        match self {
            Self::V1(header) => header.commitment(),
        }
    }
}

impl ValidiumBatchHeader for BatchHeaderValidiumV1 {
    fn commitment(&self) -> Vec<u8> {
        self.commitment.to_vec()
    }
}

impl BatchHeader for BatchHeaderValidium {
    fn version(&self) -> u8 {
        match self {
            Self::V1(header) => header.version(),
        }
    }

    fn index(&self) -> u64 {
        match self {
            Self::V1(header) => header.index(),
        }
    }

    fn parent_batch_hash(&self) -> B256 {
        match self {
            Self::V1(header) => header.parent_batch_hash(),
        }
    }

    fn batch_hash(&self) -> B256 {
        match self {
            Self::V1(header) => header.batch_hash(),
        }
    }

    fn blob_versioned_hash(&self) -> B256 {
        match self {
            Self::V1(header) => header.blob_versioned_hash(),
        }
    }
}

impl BatchHeader for BatchHeaderValidiumV1 {
    fn version(&self) -> u8 {
        self.version
    }

    fn index(&self) -> u64 {
        self.batch_index
    }

    fn parent_batch_hash(&self) -> B256 {
        self.parent_batch_hash
    }

    /// Batch hash for Validium batch header v1:
    ///
    /// keccak(
    ///     version ||
    ///     batch index ||
    ///     parent batch hash ||
    ///     post state root ||
    ///     withdraw root ||
    ///     commitment
    /// )
    fn batch_hash(&self) -> B256 {
        keccak256(
            std::iter::empty()
                .chain(vec![self.version].as_slice())
                .chain(self.batch_index.to_be_bytes().as_slice())
                .chain(self.parent_batch_hash.as_slice())
                .chain(self.post_state_root.as_slice())
                .chain(self.withdraw_root.as_slice())
                .chain(self.commitment.as_slice())
                .cloned()
                .collect::<Vec<u8>>(),
        )
    }

    fn blob_versioned_hash(&self) -> B256 {
        B256::default()
    }
}
