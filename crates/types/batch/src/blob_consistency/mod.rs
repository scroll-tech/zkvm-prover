#[cfg(feature = "openvm")]
use alloy_primitives::{B256, U256};

#[cfg(feature = "openvm")]
use openvm_pairing::bls12_381::Scalar;

mod constants;

#[cfg(feature = "openvm")]
mod openvm;
#[cfg(feature = "sp1")]
mod sp1;
#[cfg(feature = "openvm")]
mod types;

pub use constants::{BLS_MODULUS, VERSIONED_HASH_VERSION_KZG};

/// Translate a blob envelope into the full EIP-4844 blob byte layout.
///
/// Each 32-byte field element has its most-significant byte set to 0; the remaining 31 bytes are
/// filled from `envelope_bytes`. The result is backend-agnostic and can be consumed by c-kzg,
/// kzg-rs, or a polynomial representation.
pub fn envelope_to_blob_bytes(envelope_bytes: &[u8]) -> [u8; BLOB_WIDTH * N_BYTES_U256] {
    assert!(
        envelope_bytes.len() <= N_BLOB_BYTES,
        "blob-envelope bigger than allowed"
    );

    let mut blob = [0u8; BLOB_WIDTH * N_BYTES_U256];
    for (i, &byte) in envelope_bytes.iter().enumerate() {
        let field_element_index = i / N_DATA_BYTES_PER_COEFFICIENT;
        let byte_in_element = 1 + (i % N_DATA_BYTES_PER_COEFFICIENT);
        blob[field_element_index * N_BYTES_U256 + byte_in_element] = byte;
    }
    blob
}

#[cfg(feature = "openvm")]
pub use openvm::{kzg_to_versioned_hash, point_evaluation, verify_kzg_proof};
#[cfg(all(feature = "sp1", not(feature = "openvm")))]
pub use sp1::kzg_to_versioned_hash;
#[cfg(feature = "openvm")]
pub use types::ToIntrinsic;

#[cfg(feature = "sp1")]
pub use sp1::{kzg_to_versioned_hash as sp1_kzg_to_versioned_hash, verify_blob_versioned_hash};

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

/// Represents the EIP-4844 blob in its polynomial form, i.e. 4096 BLS12-381 scalar fields.
#[cfg(any(feature = "openvm", test))]
#[derive(Debug, Clone, Copy)]
pub struct BlobPolynomial([U256; BLOB_WIDTH]);

#[cfg(any(feature = "openvm", test))]
impl BlobPolynomial {
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

    #[cfg(feature = "openvm")]
    pub fn evaluate(&self, challenge_digest: B256) -> (Scalar, Scalar) {
        // blob data proof is [challenge, point_evaluation] mapped into H256
        let challenge_digest = U256::from_be_bytes(challenge_digest.0);

        point_evaluation(&self.0, challenge_digest)
    }
}
