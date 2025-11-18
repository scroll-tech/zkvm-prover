use alloy_primitives::B256;

pub mod batch;
pub mod bundle;
pub mod chunk;

pub use crate::{fork_name::ForkName, version::Version};

/// Defines behaviour to be implemented by types representing the public-input values of a circuit.
pub trait PublicInputs {
    /// Keccak-256 digest of the public inputs. The public-input hash are revealed as public values
    /// via [`openvm::io::reveal`].
    fn pi_hash(&self) -> B256;

    /// Validation logic between public inputs of two contiguous instances.
    fn validate(&self, prev_pi: &Self);
}

/// helper trait to extend PublicInputs
pub trait MultiVersionPublicInputs {
    fn pi_hash_by_version(&self, version: Version) -> B256;
    fn validate(&self, prev_pi: &Self, version: Version);
}

impl<T: MultiVersionPublicInputs> PublicInputs for (T, Version) {
    fn pi_hash(&self) -> B256 {
        self.0.pi_hash_by_version(self.1)
    }

    fn validate(&self, prev_pi: &Self) {
        // version remains unchanged.
        assert_eq!(self.1.as_version_byte(), prev_pi.1.as_version_byte());

        // perform inner validation.
        self.0.validate(&prev_pi.0, self.1)
    }
}
