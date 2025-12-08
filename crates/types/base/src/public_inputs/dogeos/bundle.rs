use crate::public_inputs::{scroll, MultiVersionPublicInputs, Version};

/// Represents fields required to compute the public-inputs digest of a bundle.
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DogeOsBundleInfo {
    pub inner: scroll::bundle::BundleInfo,
}

pub type VersionedDogeOsBundleInfo = (DogeOsBundleInfo, Version);

impl MultiVersionPublicInputs for DogeOsBundleInfo {
    fn pi_by_version(&self, version: Version) -> Vec<u8> {
        self.inner.pi_by_version(version)
    }

    fn validate(&self, prev_pi: &Self, version: Version) {
        self.inner.validate(&prev_pi.inner, version)
    }
}
