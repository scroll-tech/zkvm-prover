use alloy_primitives::B256;

mod header;
pub use header::{
    ArchivedReferenceHeader, BatchHeader, ReferenceHeader,
    v3::{ArchivedBatchHeaderV3, BatchHeaderV3},
};

mod public_inputs;
pub use public_inputs::{ArchivedBatchInfo, BatchInfo};

mod witness;
pub use witness::{ArchivedBatchWitness, BatchWitness};

/// The upper bound for the number of chunks that can be aggregated in a single batch.
pub const MAX_AGG_CHUNKS: usize = 45;

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

/// Generic for batch header types which also contain information of its parent
pub struct AsLastBatchHeader<'a, T: KnownLastBatchHash + BatchHeader>(pub &'a T);

impl<T: KnownLastBatchHash + BatchHeader> BatchHeader for AsLastBatchHeader<'_, T> {
    fn version(&self) -> u8 {
        self.0.version()
    }

    fn index(&self) -> u64 {
        self.0.index() - 1
    }

    fn batch_hash(&self) -> B256 {
        self.0.parent_batch_hash()
    }
}
