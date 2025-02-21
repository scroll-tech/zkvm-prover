// TODO: should we rename as "public_inputs_legacy"?
//#[cfg(not(feature = "euclidv2"))]
pub mod public_inputs;
#[cfg(not(feature = "euclidv2"))]
pub use public_inputs::{ArchivedChunkInfo, ChunkInfo};
//#[cfg(feature = "euclidv2")]
pub mod public_inputs_euclidv2;
#[cfg(feature = "euclidv2")]
pub use public_inputs_euclidv2::{ArchivedChunkInfo, BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX};

#[cfg(feature = "scroll")]
mod utils;

#[cfg(feature = "scroll")]
mod witness;
#[cfg(feature = "scroll")]
pub use {
    utils::make_providers,
    witness::{ArchivedChunkWitness, ChunkWitness},
};

mod execute;
pub use execute::execute;
