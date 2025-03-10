pub mod public_inputs_legacy;
#[cfg(not(feature = "euclidv2"))]
pub use public_inputs_legacy::{ArchivedChunkInfo, ChunkInfo};
pub mod public_inputs_euclidv2;
#[cfg(feature = "euclidv2")]
pub use public_inputs_euclidv2::{ArchivedChunkInfo, BlockContextV2, ChunkInfo, SIZE_BLOCK_CTX};

mod utils;

mod witness;

pub use utils::make_providers;
pub use witness::{ArchivedChunkWitness, ChunkWitness};

mod execute;
pub use execute::execute;
