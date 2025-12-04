use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfo;
use crate::scroll;

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DogeOsChunkWitness {
    /// Scroll ChunkWitness
    pub inner: scroll::ChunkWitness,
    // Other DogeOs-specific fields can be added here
    // ...
}

impl TryFrom<DogeOsChunkWitness> for DogeOsChunkInfo {
    type Error = String;

    fn try_from(value: DogeOsChunkWitness) -> Result<Self, Self::Error> {
        super::execute(value)
    }
}
