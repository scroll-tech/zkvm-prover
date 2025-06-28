mod header;
pub use header::{
    ArchivedReferenceHeader, BatchHeader, ReferenceHeader,
    v6::{ArchivedBatchHeaderV6, BatchHeaderV6},
    v7::{ArchivedBatchHeaderV7, BatchHeaderV7},
    v8::{ArchivedBatchHeaderV8, BatchHeaderV8},
};

mod payload;
pub use payload::{
    v6::{EnvelopeV6, PayloadV6},
    v7::{EnvelopeV7, PayloadV7},
    v8::{EnvelopeV8, PayloadV8},
};

mod blob_consistency;
mod builder;

pub use payload::{BLOB_WIDTH, N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT};

mod witness;
pub use witness::{ArchivedBatchWitness, BatchWitness, Bytes48, PointEvalWitness};
