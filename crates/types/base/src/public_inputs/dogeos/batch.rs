use crate::public_inputs::{MultiVersionPublicInputs, scroll};
use crate::version::Version;

/// Represents public-input values for a batch.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DogeOsBatchInfo {
    pub inner: scroll::batch::BatchInfo,
    pub extras: DogeOsBatchInfoExtras,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct DogeOsBatchInfoExtras {
    // Add DogeOs-specific extra fields here if needed in the future
}

pub type VersionedDogeOsBatchInfo = (DogeOsBatchInfo, Version);

impl MultiVersionPublicInputs for DogeOsBatchInfo {
    fn pi_by_version(&self, version: Version) -> Vec<u8> {
        self.inner.pi_by_version(version)
    }

    fn validate(&self, prev_pi: &Self, version: Version) {
        self.inner.validate(&prev_pi.inner, version)
    }
}
