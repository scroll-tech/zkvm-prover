use alloy_primitives::{B256 as H256, U256};

#[cfg(feature = "common_curve")]
mod general;
#[cfg(feature = "common_curve")]
use general::point_evaluation;

#[cfg(not(feature = "common_curve"))]
mod openvm;
#[cfg(not(feature = "common_curve"))]
use openvm::point_evaluation;

// Number of bytes in a u256.
pub const N_BYTES_U256: usize = 32;

/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;

/// The number of BLS12-381 scalar fields that effectively represent an EIP-4844 blob.
pub const BLOB_WIDTH: usize = 4096;

/// Base 2 logarithm of `BLOB_WIDTH`.
pub const LOG_BLOB_WIDTH: usize = 12;

/// The effective (reduced) number of bytes we can use within a blob.
///
/// EIP-4844 requires that each 32-bytes chunk of bytes represent a BLS12-381 scalar field element
/// in its canonical form. As a result, we set the most-significant byte in each such chunk to 0.
/// This allows us to use only up to 31 bytes in each such chunk, hence the reduced capacity.
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

/// Helper structures to verify blob data, basically it is just the coefficients parsed from blob data
#[derive(Debug, Clone, Copy)]
pub struct BlobConsistency([U256; BLOB_WIDTH]);

impl BlobConsistency {
    pub fn new(blob_bytes: &[u8]) -> Self {
        let mut coefficients = [[0u8; N_BYTES_U256]; BLOB_WIDTH];

        assert!(
            blob_bytes.len() <= N_BLOB_BYTES,
            "too many bytes in batch data"
        );

        for (i, &byte) in blob_bytes.iter().enumerate() {
            coefficients[i / 31][1 + (i % 31)] = byte;
        }

        Self(coefficients.map(|coeff| U256::from_be_bytes(coeff)))
    }

    pub fn blob_data_proof(&self, challenge_digest: H256) -> [H256; 2] {
        // blob data proof is [challenge, point_evaluation] mapped into H256
        let challenge_digest = U256::from_be_bytes(challenge_digest.0);

        #[cfg(feature = "common_curve")]
        let (challenge, evaluation) = point_evaluation(&self.0, challenge_digest);

        #[cfg(not(feature = "common_curve"))]
        let (challenge, evaluation) = point_evaluation(&self.0, challenge_digest);

        [challenge, evaluation].map(|u| H256::new(u.to_be_bytes()))
    }
}
