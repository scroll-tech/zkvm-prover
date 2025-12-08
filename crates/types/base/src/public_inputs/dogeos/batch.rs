use crate::public_inputs::{scroll, MultiVersionPublicInputs};
use crate::version::Version;

/// Represents public-input values for a batch.
#[derive(
    Clone,
    Debug,
    rkyv::Archive,
    rkyv::Deserialize,
    rkyv::Serialize,
    serde::Deserialize,
    serde::Serialize,
)]
#[rkyv(derive(Debug))]
pub struct DogeOsBatchInfo {
    pub inner: scroll::batch::BatchInfo
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
