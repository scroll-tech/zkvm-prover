use crate::public_inputs::MultiVersionPublicInputs;
use crate::public_inputs::{Version, scroll};
use alloy_primitives::B256;

/// Represents header-like information for the chunk.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DogeOsChunkInfo {
    /// Scroll ChunkInfo
    pub inner: scroll::chunk::ChunkInfo,
    /// DogeOs-specific fields
    pub extras: DogeOsChunkInfoExtras,
}

/// DogeOs-specific fields can be added here
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DogeOsChunkInfoExtras {
    /// The starting dogecoin blockhash of the chunk.
    pub start_blockhash: B256,
    /// The ending dogecoin blockhash of the chunk.
    pub end_blockhash: B256,
}

impl From<(scroll::chunk::ChunkInfo, DogeOsChunkInfoExtras)> for DogeOsChunkInfo {
    fn from(value: (scroll::chunk::ChunkInfo, DogeOsChunkInfoExtras)) -> Self {
        DogeOsChunkInfo {
            inner: value.0,
            extras: value.1,
        }
    }
}

pub type VersionedDogeOsChunkInfo = (DogeOsChunkInfo, Version);

impl MultiVersionPublicInputs for DogeOsChunkInfo {
    fn pi_by_version(&self, version: Version) -> Vec<u8> {
        let mut scroll_chunk_pi = self.inner.pi_by_version(version);

        scroll_chunk_pi.extend_from_slice(self.extras.start_blockhash.as_slice());
        scroll_chunk_pi.extend_from_slice(self.extras.end_blockhash.as_slice());
        scroll_chunk_pi
    }

    fn validate(&self, prev_pi: &Self, version: Version) {
        self.inner.validate(&prev_pi.inner, version);
        // dogecoin blockhash linkage check enforce no deposit tx can be skipped
        assert_eq!(self.extras.start_blockhash, prev_pi.extras.end_blockhash);
    }
}
