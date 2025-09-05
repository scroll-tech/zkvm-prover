#[cfg(feature = "host")]
pub mod point_eval {
    use crate::blob_consistency::kzg_to_versioned_hash;

    use c_kzg;
    use sbv_primitives::{B256 as H256, U256, types::eips::eip4844::BLS_MODULUS};

    /// Given the blob-envelope, translate it to a fixed size EIP-4844 blob.
    ///
    /// For every 32-bytes chunk in the blob, the most-significant byte is set to 0 while the other
    /// 31 bytes are copied from the provided blob-envelope.
    pub fn to_blob(envelope_bytes: &[u8]) -> c_kzg::Blob {
        let mut blob_bytes = [0u8; c_kzg::BYTES_PER_BLOB];

        assert!(
            envelope_bytes.len()
                <= c_kzg::FIELD_ELEMENTS_PER_BLOB * (c_kzg::BYTES_PER_FIELD_ELEMENT - 1),
            "too many bytes in blob envelope",
        );

        for (i, &byte) in envelope_bytes.iter().enumerate() {
            blob_bytes[(i / 31) * 32 + 1 + (i % 31)] = byte;
        }

        c_kzg::Blob::new(blob_bytes)
    }

    /// Get the KZG commitment from an EIP-4844 blob.
    pub fn blob_to_kzg_commitment(blob: &c_kzg::Blob) -> c_kzg::KzgCommitment {
        c_kzg::ethereum_kzg_settings(0)
            .blob_to_kzg_commitment(blob)
            .expect("blob to kzg commitment should succeed")
    }

    /// Get the EIP-4844 versioned hash from the KZG commitment.
    pub fn get_versioned_hash(commitment: &c_kzg::KzgCommitment) -> H256 {
        H256::new(kzg_to_versioned_hash(commitment.to_bytes().as_slice()))
    }

    /// Get x for kzg proof from challenge hash
    pub fn get_x_from_challenge(challenge: H256) -> U256 {
        U256::from_be_bytes(challenge.0) % BLS_MODULUS
    }

    /// Generate KZG proof and evaluation given the blob (polynomial) and a random challenge.
    pub fn get_kzg_proof(blob: &c_kzg::Blob, challenge: H256) -> (c_kzg::KzgProof, U256) {
        let challenge = get_x_from_challenge(challenge);

        let (proof, y) = c_kzg::ethereum_kzg_settings(0)
            .compute_kzg_proof(blob, &c_kzg::Bytes32::new(challenge.to_be_bytes()))
            .expect("kzg proof should succeed");

        (proof, U256::from_be_slice(y.as_slice()))
    }
}
