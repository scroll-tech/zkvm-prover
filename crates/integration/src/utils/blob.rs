
use sbv::primitives::{B256 as H256, U256};
use sha2::{Digest, Sha256};


// Number of bytes in a u256.
const N_BYTES_U256: usize = 32;
/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;
const BLOB_WIDTH: usize = 4096;
const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

/// Get the BLOB_WIDTH number of scalar field elements, as 32-bytes unsigned integers.
fn get_coefficients(blob_bytes: &[u8]) -> [U256; BLOB_WIDTH] {
    let mut coefficients = [[0u8; N_BYTES_U256]; BLOB_WIDTH];

    assert!(
        blob_bytes.len() <= N_BLOB_BYTES,
        "too many bytes in batch data"
    );

    for (i, &byte) in blob_bytes.iter().enumerate() {
        coefficients[i / 31][1 + (i % 31)] = byte;
    }

    coefficients.map(|coeff| U256::from_be_bytes(coeff))
}

/// Get the versioned hash as per EIP-4844.
pub fn get_versioned_hash(blob_bytes: &[u8]) -> H256 {

    let coefficients = get_coefficients(blob_bytes);

    let blob = c_kzg::Blob::from_bytes(
        &coefficients
            .iter()
            .cloned()
            .flat_map(|coeff| coeff.to_be_bytes::<32>())
            .collect::<Vec<_>>(),
    )
    .expect("blob-coefficients to 4844 blob should succeed");
    let c = c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, c_kzg::ethereum_kzg_settings())
        .expect("blob to kzg commitment should succeed");
    kzg_to_versioned_hash(&c)
}

fn kzg_to_versioned_hash(commitment: &c_kzg::KzgCommitment) -> H256 {
    let mut res = Sha256::digest(commitment.as_slice());
    res[0] = 0x1; // VERSIONED_HASH_VERSION_KZG
    H256::from_slice(&res[..])
}
