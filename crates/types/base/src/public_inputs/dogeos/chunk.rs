use crate::public_inputs::{scroll, Version};
use crate::public_inputs::MultiVersionPublicInputs;

/// Represents header-like information for the chunk.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DogeOsChunkInfo {
    /// Scroll ChunkInfo
    pub inner: scroll::chunk::ChunkInfo,
    // DogeOs-specific fields can be added here
    /// The starting dogecoin blockhash of the chunk.
    pub start_blockhash: [u8; 32],
    /// The ending dogecoin blockhash of the chunk.
    pub end_blockhash: [u8; 32],
}

pub type VersionedDogeOsChunkInfo = (DogeOsChunkInfo, Version);


impl MultiVersionPublicInputs for DogeOsChunkInfo {
    fn pi_by_version(&self, version: Version) -> Vec<u8> {
        let mut scroll_chunk_pi = self.inner.pi_by_version(version);

        scroll_chunk_pi.extend_from_slice(&self.start_blockhash);
        scroll_chunk_pi.extend_from_slice(&self.end_blockhash);
        scroll_chunk_pi
    }

    fn validate(&self, prev_pi: &Self, version: Version) {
        self.inner.validate(&prev_pi.inner, version);
        // dogecoin blockhash linkage check enforce no deposit tx can be skipped
        assert_eq!(self.start_blockhash, prev_pi.end_blockhash);
    }
}
