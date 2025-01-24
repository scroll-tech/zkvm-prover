
use sbv::primitives::{B256 as H256, U256};
use sha2::{Digest, Sha256};
use bls12_381::Scalar;
use ff::PrimeField;

// Number of bytes in a u256.
const N_BYTES_U256: usize = 32;
/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;
const BLOB_WIDTH: usize = 4096;
const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

/// Get the BLOB_WIDTH number of scalar field elements, as 32-bytes unsigned integers.
pub fn get_coefficients(blob_bytes: &[u8]) -> [U256; BLOB_WIDTH] {
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
pub fn get_versioned_hash(coefficients: &[U256; BLOB_WIDTH]) -> H256 {

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

use std::sync::LazyLock;
// Base 2 logarithm of `BLOB_WIDTH`.
const LOG_BLOB_WIDTH: usize = 12;

static BLS_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    U256::from_str_radix(&Scalar::MODULUS[2..], 16).expect("BLS_MODULUS from bls crate")
});

static ROOTS_OF_UNITY: LazyLock<Vec<Scalar>> = LazyLock::new(|| {
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = Scalar::from(7);
    let modulus = *BLS_MODULUS;

    let exponent = (modulus - U256::from(1)) / U256::from(4096);
    let root_of_unity = primitive_root_of_unity.pow(exponent.as_limbs());

    let ascending_order: Vec<_> =
        std::iter::successors(Some(Scalar::one()), |x| Some(*x * root_of_unity))
            .take(BLOB_WIDTH)
            .collect();

    (0..BLOB_WIDTH)
        .map(|i| {
            let j = u16::try_from(i).unwrap().reverse_bits() >> (16 - LOG_BLOB_WIDTH);
            ascending_order[usize::from(j)]
        })
        .collect()
});

fn interpolate(z: Scalar, coefficients: &[Scalar; BLOB_WIDTH]) -> Scalar {
    let blob_width = u64::try_from(BLOB_WIDTH).unwrap();
    (z.pow(&[blob_width, 0, 0, 0]) - Scalar::one())
        * ROOTS_OF_UNITY
            .iter()
            .zip(coefficients)
            .map(|(root, f)| f * root * (z - root).invert().unwrap())
            .sum::<Scalar>()
        * Scalar::from(blob_width).invert().unwrap()
}

pub fn point_evaluation(coefficients: &[U256; BLOB_WIDTH], challenge_digest: U256) -> (U256, U256) {
    // blob polynomial in evaluation form.
    //
    // also termed P(x)
    let coefficients_as_scalars = coefficients.map(|coeff| Scalar::from_raw(*coeff.as_limbs()));

    let challenge = challenge_digest % *BLS_MODULUS;

    // y = P(z)
    let y = U256::from_le_bytes(
        interpolate(
            Scalar::from_raw(*challenge.as_limbs()),
            &coefficients_as_scalars,
        )
        .to_bytes(),
    );

    (challenge, y)
}
