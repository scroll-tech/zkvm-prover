pub mod v6;
pub use v6::BatchInfoBuilderV6;

pub mod v7;
pub use v7::BatchInfoBuilderV7;

pub mod validium;

use types_base::public_inputs::scroll::{batch::BatchInfo, chunk::ChunkInfo};

use crate::{BatchHeader, BatchHeaderV6, BatchHeaderV7, PointEvalWitness, payload::Payload};

pub struct BuilderArgs<Header: BatchHeader> {
    pub header: Header,
    pub chunk_infos: Vec<ChunkInfo>,
    pub blob_bytes: Vec<u8>,
    pub point_eval_witness: Option<PointEvalWitness>,
}

pub type BuilderArgsV6 = BuilderArgs<BatchHeaderV6>;
pub type BuilderArgsV7 = BuilderArgs<BatchHeaderV7>;

pub trait BatchInfoBuilder {
    type Payload: Payload;

    /// Build the public-input values [`BatchInfo`] for the [`BatchCircuit`][crate::circuit::BatchCircuit]
    /// by processing the witness, while making some validations.
    fn build(version: u8, args: BuilderArgs<<Self::Payload as Payload>::BatchHeader>) -> BatchInfo;
}
