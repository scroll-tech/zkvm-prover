mod header;
pub use header::{
    BatchHeader, ReferenceHeader, v6::BatchHeaderV6, v7::BatchHeaderV7, v8::BatchHeaderV8,
};

mod payload;
pub use payload::{
    BLOB_WIDTH, Envelope, N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT, Payload,
    v6::{EnvelopeV6, PayloadV6},
    v7::{EnvelopeV7, PayloadV7},
    v8::{EnvelopeV8, PayloadV8},
};

pub mod blob_consistency;
mod builder;

mod witness;
pub use witness::{BatchWitness, Bytes48, PointEvalWitness, PointEvalWitnessHints};
