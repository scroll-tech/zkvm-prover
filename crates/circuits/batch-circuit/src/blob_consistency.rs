use alloy_primitives::{B256 as H256, U256};

// Number of bytes in a u256.
pub const N_BYTES_U256: usize = 32;
/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;
pub const BLOB_WIDTH: usize = 4096;
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

#[cfg(feature = "common_curve")]
mod general;
mod openvm;

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
        let (challenge, evaluation) = general::point_evaluation(&self.0, challenge_digest);

        #[cfg(not(feature = "common_curve"))]
        let (challenge, evaluation) = openvm::point_evaluation(&self.0, challenge_digest);

        [challenge, evaluation].map(|u| H256::new(u.to_be_bytes()))
    }
}
