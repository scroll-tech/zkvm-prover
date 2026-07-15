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

#[cfg(any(feature = "openvm", feature = "sp1"))]
pub mod blob_consistency;

#[cfg(feature = "openvm")]
mod builder;

mod witness;
#[cfg(any(feature = "openvm", feature = "sp1"))]
pub use witness::build_point_eval_witness;
pub use witness::{BatchWitness, Bytes48, PointEvalWitness};

pub mod utils;
