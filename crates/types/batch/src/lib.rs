mod header;
pub use header::{
    BatchHeader, ReferenceHeader,
    v6::BatchHeaderV6,
    v7::BatchHeaderV7,
    validium::{BatchHeaderValidium, BatchHeaderValidiumV1},
};

mod payload;
pub use payload::{
    BLOB_WIDTH, Envelope, N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT, Payload,
    v6::{EnvelopeV6, PayloadV6},
    v7::{EnvelopeV7, PayloadV7},
};

pub mod blob_consistency;
mod builder;

mod witness;
pub use witness::{BatchWitness, Bytes48, PointEvalWitness, build_point_eval_witness};

pub mod dogeos;

pub mod utils;
