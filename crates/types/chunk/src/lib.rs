#[cfg(feature = "openvm")]
mod crypto;
mod types;
mod witness;

pub use alloy_consensus;
#[cfg(feature = "openvm")]
pub use crypto::Crypto;
pub use sbv_primitives::Address;
pub use sbv_primitives::types::revm::precompile as revm_precompile;
pub use witness::{ChunkWitness, ChunkWitnessWithRspTrie, LegacyChunkWitness};

mod execute;
pub use execute::execute;
