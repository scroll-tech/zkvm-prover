use crate::scroll::ChunkWitness;

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DogeOsChunkWitness {
    /// Scroll ChunkWitness
    pub inner: ChunkWitness,
    /// Other DogeOs-specific fields can be added here
    /// ...
}
