use crate::utils::keccak256;
use alloy_primitives::B256;

pub mod scroll;

pub use crate::{fork_name::ForkName, version::Version};

/// Defines behaviour to be implemented by types representing the public-input values of a circuit.
pub trait PublicInputs {
    /// Public inputs encoded.
    fn pi(&self) -> Vec<u8>;

    /// Keccak-256 digest of the public inputs. The public-input hash are revealed as public values
    /// via [`openvm::io::reveal`].
    fn pi_hash(&self) -> B256 {
        keccak256(self.pi())
    }

    /// Validation logic between public inputs of two contiguous instances.
    fn validate(&self, prev_pi: &Self);
}

/// helper trait to extend PublicInputs
pub trait MultiVersionPublicInputs {
    /// Public inputs encoded for a specific version.
    fn pi_by_version(&self, version: Version) -> Vec<u8>;
    /// Keccak-256 digest of the public inputs for a specific version.
    fn pi_hash_by_version(&self, version: Version) -> B256 {
        keccak256(self.pi_by_version(version))
    }
    fn validate(&self, prev_pi: &Self, version: Version);
}

impl<T: MultiVersionPublicInputs> PublicInputs for (T, Version) {
    fn pi(&self) -> Vec<u8> {
        self.0.pi_by_version(self.1)
    }

    fn validate(&self, prev_pi: &Self) {
        // version remains unchanged.
        assert_eq!(self.1.as_version_byte(), prev_pi.1.as_version_byte());

        // perform inner validation.
        self.0.validate(&prev_pi.0, self.1)
    }
}
