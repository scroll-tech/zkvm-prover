mod header;
pub use header::{
    ArchivedReferenceHeader, BatchHeader, ReferenceHeader,
    v3::{ArchivedBatchHeaderV3, BatchHeaderV3},
    v7::{ArchivedBatchHeaderV7, BatchHeaderV7},
};

mod public_inputs;
pub use public_inputs::{ArchivedBatchInfo, BatchInfo};

mod witness;
pub use witness::{ArchivedBatchWitness, BatchWitness};

/// The upper bound for the number of chunks that can be aggregated in a single batch.
pub const MAX_AGG_CHUNKS: usize = 45;
