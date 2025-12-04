use crate::public_inputs::{scroll, Version};
use crate::public_inputs::MultiVersionPublicInputs;

/// Represents header-like information for the chunk.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DogeOsChunkInfo {
    /// Scroll ChunkInfo
    pub inner: scroll::chunk::ChunkInfo,
    // Other DogeOs-specific fields can be added here
    // ...
}

pub type VersionedDogeOsChunkInfo = (DogeOsChunkInfo, Version);


impl MultiVersionPublicInputs for DogeOsChunkInfo {
    fn pi_by_version(&self, version: Version) -> Vec<u8> {
        let scroll_chunk_pi = self.inner.pi_by_version(version);

        scroll_chunk_pi
    }

    fn validate(&self, prev_pi: &Self, version: Version) {
        self.inner.validate(&prev_pi.inner, version)
    }
}
