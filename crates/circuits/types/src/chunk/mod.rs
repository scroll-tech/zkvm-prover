mod public_inputs;
pub use public_inputs::{ArchivedChunkInfo, BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX};

#[cfg(feature = "scroll")]
mod utils;

#[cfg(feature = "scroll")]
mod witness;
#[cfg(feature = "scroll")]
pub use {
    utils::make_providers,
    witness::{ArchivedChunkWitness, ChunkWitness},
};
