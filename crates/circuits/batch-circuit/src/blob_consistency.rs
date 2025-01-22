use core::unimplemented;

use alloy_primitives::{Address, BlockNumber, Bloom, Bytes, B256 as H256, B64, U256};

// Number of bytes in a u256.
pub const N_BYTES_U256: usize = 32;
/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;
pub const BLOB_WIDTH: usize = 4096;
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

#[cfg(feature="gen_curve")]
mod general;
mod openvm;

/// Helper structures to verify blob data, basically it is just the coefficients parsed from blob data
#[derive(Debug, Clone, Copy)]
pub struct BlobConsistency ([U256; BLOB_WIDTH]);

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

    /// Get the versioned hash as per EIP-4844. It has to be calculated OUTSIDE
    /// of zkvm program
    pub fn versioned_hash(&self) -> H256 {
        unimplemented!();
        // TODO: need the kzg commitment as the hash of coefficients (i.e. BlobHash in evm?)

        // let blob = c_kzg::Blob::from_bytes(
        //     &coefficients
        //         .iter()
        //         .cloned()
        //         .flat_map(|coeff| self.0.to_be_bytes())
        //         .collect::<Vec<_>>(),
        // )
        // .expect("blob-coefficients to 4844 blob should succeed");
        // let c = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, &KZG_TRUSTED_SETUP)
        //     .expect("blob to kzg commitment should succeed");
        // kzg_to_versioned_hash(&c)
    }

    pub fn blob_data_proof(&self, challenge_digest: H256) -> [H256; 2] {
        // blob data proof is [challenge, point_evaluation] mapped into H256
        let challenge_digest = U256::from_be_bytes(challenge_digest.0);

        #[cfg(feature="gen_curve")]
        let (challenge, evaluation) = general::point_evaluation(&self.0, challenge_digest);

        #[cfg(not(feature="gen_curve"))]
        let (challenge, evaluation) = openvm::point_evaluation(&self.0, challenge_digest);

        [challenge, evaluation].map(|u|H256::new(u.to_be_bytes()))
    }
} 