//#[cfg(not(feature = "euclidv2"))]
pub mod public_inputs_legacy;
#[cfg(not(feature = "euclidv2"))]
pub use public_inputs_legacy::{ArchivedChunkInfo, ChunkInfo};
//#[cfg(feature = "euclidv2")]
pub mod public_inputs_euclidv2;
#[cfg(feature = "euclidv2")]
pub use public_inputs_euclidv2::{ArchivedChunkInfo, BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX};

#[cfg(feature = "sbv")]
mod utils;

#[cfg(feature = "sbv")]
mod witness;

#[cfg(feature = "sbv")]
pub use {
    utils::make_providers,
    witness::{ArchivedChunkWitness, ChunkWitness},
};

mod execute;
pub use execute::execute;
