mod header;
pub use header::{
    ArchivedReferenceHeader, BatchHeader, ReferenceHeader,
    v3::{ArchivedBatchHeaderV3, BatchHeaderV3},
    v7::{ArchivedBatchHeaderV7, BatchHeaderV7},
};

mod payload;
#[cfg(not(feature = "euclidv2"))]
pub use payload::v3::{EnvelopeV3, PayloadV3};
#[cfg(feature = "euclidv2")]
pub use payload::v7::{EnvelopeV7, PayloadV7};

pub use payload::{BLOB_WIDTH, LOG_BLOB_WIDTH, N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT};

mod public_inputs;
pub use public_inputs::{ArchivedBatchInfo, BatchInfo};

mod witness;
pub use witness::{ArchivedBatchWitness, BatchWitness, Bytes48, PointEvalWitness};
