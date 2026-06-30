#![cfg(feature = "sp1")]

use alloy_primitives::{B256, U256};
use bls12_381::G1Affine;
use kzg_rs::{
    KzgProof, KzgSettings,
    dtypes::{Blob, Bytes32, Bytes48},
    kzg_proof::evaluate_polynomial_in_evaluation_form,
};
use sha2::{Digest, Sha256};

use super::{BLS_MODULUS, N_BLOB_BYTES, VERSIONED_HASH_VERSION_KZG, envelope_to_blob_bytes};
use crate::PointEvalWitness;

/// Compute the versioned hash based on KZG scheme in EIP-4844.
pub fn kzg_to_versioned_hash(kzg_commitment: &[u8]) -> [u8; 32] {
    let mut hash: [u8; 32] = Sha256::digest(kzg_commitment).into();
    hash[0] = VERSIONED_HASH_VERSION_KZG;
    hash
}

/// Verify that `blob_bytes` is consistent with `blob_versioned_hash` using the EIP-4844
/// point-evaluation witness.
///
/// The implementation is backed by `kzg-rs` running on SP1's BLS12-381 precompiles.
/// It evaluates the blob polynomial at the Scroll challenge point and then verifies the
/// supplied KZG proof for that evaluation.
pub fn verify_blob_versioned_hash(
    blob_bytes: &[u8],
    blob_versioned_hash: B256,
    challenge_digest: B256,
    witness: &PointEvalWitness,
) {
    assert!(
        blob_bytes.len() <= N_BLOB_BYTES,
        "blob-envelope bigger than allowed"
    );

    // Reconstruct the full EIP-4844 blob (4096 32-byte field elements, MSB zeroed).
    let blob =
        Blob::from_slice(&envelope_to_blob_bytes(blob_bytes)).expect("invalid blob bytes");

    // `kzg-rs` is patched for the SP1 target so that `load_trusted_setup_file()` returns a static
    // copy of the EIP-4844 trusted setup rather than reading from the (non-existent) guest fs.
    // See the `kzg-rs` fork at `https://github.com/succinctlabs/kzg-rs` tag `v0.2.8-sp1-6.2.0`.

    // Reconstruct compressed KZG commitment/proof from the uncompressed (x, y) witness.
    let commitment = compressed_from_xy(&witness.kzg_commitment_x, &witness.kzg_commitment_y);
    let proof = compressed_from_xy(&witness.kzg_proof_x, &witness.kzg_proof_y);

    // Derive the challenge scalar from the Scroll challenge digest.
    let challenge = U256::from_be_bytes(challenge_digest.0) % BLS_MODULUS;
    let challenge_bytes = challenge.to_be_bytes::<32>();
    let challenge_scalar = kzg_rs::kzg_proof::safe_scalar_affine_from_bytes(
        &Bytes32::from_slice(&challenge_bytes).expect("invalid challenge length"),
    )
    .expect("challenge not a valid BLS scalar");

    // Evaluate the blob polynomial at the challenge point.
    let settings = KzgSettings::load_trusted_setup_file().expect("failed to load KZG settings");
    let polynomial = blob.as_polynomial().expect("failed to parse blob polynomial");
    let evaluation = evaluate_polynomial_in_evaluation_form(
        polynomial,
        challenge_scalar,
        &settings,
    )
    .expect("failed to evaluate blob polynomial");

    // kzg-rs `Scalar::to_bytes()` is little-endian, but `verify_kzg_proof` expects big-endian.
    let mut evaluation_be = evaluation.to_bytes();
    evaluation_be.reverse();

    // Verify the KZG proof for P(challenge) == evaluation.
    let proof_ok = KzgProof::verify_kzg_proof(
        &Bytes48::from_slice(&commitment).expect("invalid commitment length"),
        &Bytes32::from_slice(&challenge_bytes).expect("invalid challenge length"),
        &Bytes32::from_slice(&evaluation_be).expect("invalid evaluation length"),
        &Bytes48::from_slice(&proof).expect("invalid proof length"),
        &settings,
    )
    .expect("KZG proof verification errored");
    assert!(proof_ok, "verify_kzg_proof failed");

    // Verify that the KZG commitment matches the on-chain versioned hash.
    assert_eq!(
        kzg_to_versioned_hash(&commitment),
        blob_versioned_hash.0,
        "kzg_to_versioned_hash mismatch"
    );
}

fn compressed_from_xy(x: &[u8; 48], y: &[u8; 48]) -> [u8; 48] {
    let mut uncompressed = [0u8; 96];
    uncompressed[..48].copy_from_slice(x);
    uncompressed[48..].copy_from_slice(y);

    let g1: G1Affine = Option::from(G1Affine::from_uncompressed(&uncompressed))
        .expect("invalid uncompressed G1 point");
    g1.to_compressed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kzg_rs_evaluation_matches_ckzg() {
        let mut blob_bytes = [0u8; kzg_rs::BYTES_PER_BLOB];
        blob_bytes[1] = 0xab;
        blob_bytes[33] = 0xcd;

        let blob = Blob::from_slice(&blob_bytes).unwrap();
        let settings = KzgSettings::load_trusted_setup_file().unwrap();
        let polynomial = blob.as_polynomial().unwrap();

        // Pick an arbitrary challenge scalar.
        let challenge_bytes = {
            let mut b = [0u8; 32];
            b[31] = 0x42;
            b
        };
        let challenge =
            kzg_rs::kzg_proof::safe_scalar_affine_from_bytes(&Bytes32::from_slice(&challenge_bytes).unwrap())
                .unwrap();

        let y = evaluate_polynomial_in_evaluation_form(polynomial, challenge, &settings).unwrap();

        let ckzg_blob = c_kzg::Blob::new(blob_bytes);
        let (_proof, ckzg_y) = c_kzg::ethereum_kzg_settings(0)
            .compute_kzg_proof(&ckzg_blob, &c_kzg::Bytes32::new(challenge_bytes))
            .unwrap();

        // kzg-rs `Scalar::to_bytes()` is little-endian; c-kzg returns big-endian.
        let mut y_be = y.to_bytes();
        y_be.reverse();
        assert_eq!(y_be.as_slice(), ckzg_y.as_slice());
    }

    #[test]
    fn kzg_rs_blob_proof_matches_ckzg() {
        let mut blob_bytes = [0u8; kzg_rs::BYTES_PER_BLOB];
        blob_bytes[1] = 0xab;
        blob_bytes[33] = 0xcd;

        let blob = Blob::from_slice(&blob_bytes).unwrap();
        let settings = KzgSettings::load_trusted_setup_file().unwrap();

        let ckzg_blob = c_kzg::Blob::new(blob_bytes);
        let ckzg_commitment = c_kzg::ethereum_kzg_settings(0)
            .blob_to_kzg_commitment(&ckzg_blob)
            .unwrap();
        let ckzg_proof = c_kzg::ethereum_kzg_settings(0)
            .compute_blob_kzg_proof(&ckzg_blob, &ckzg_commitment.to_bytes())
            .unwrap();

        let ok = KzgProof::verify_blob_kzg_proof(
            blob,
            &Bytes48::from_slice(ckzg_commitment.to_bytes().as_ref()).unwrap(),
            &Bytes48::from_slice(ckzg_proof.to_bytes().as_ref()).unwrap(),
            &settings,
        )
        .unwrap();
        assert!(ok);
    }

    #[test]
    fn kzg_rs_standard_challenge_eval_matches_ckzg() {
        let mut blob_bytes = [0u8; kzg_rs::BYTES_PER_BLOB];
        blob_bytes[1] = 0xab;
        blob_bytes[33] = 0xcd;

        let blob = Blob::from_slice(&blob_bytes).unwrap();
        let settings = KzgSettings::load_trusted_setup_file().unwrap();
        let polynomial = blob.as_polynomial().unwrap();

        let ckzg_blob = c_kzg::Blob::new(blob_bytes);
        let ckzg_commitment = c_kzg::ethereum_kzg_settings(0)
            .blob_to_kzg_commitment(&ckzg_blob)
            .unwrap();
        let standard_challenge =
            kzg_rs::kzg_proof::compute_challenge(&blob, &{
                let g1: G1Affine = Option::from(G1Affine::from_compressed(
                    ckzg_commitment.to_bytes().as_ref(),
                ))
                .unwrap();
                g1
            })
            .unwrap();

        let y = evaluate_polynomial_in_evaluation_form(
            polynomial,
            standard_challenge,
            &settings,
        )
        .unwrap();

        let mut standard_challenge_be = standard_challenge.to_bytes();
        standard_challenge_be.reverse();
        let (_proof, ckzg_y) = c_kzg::ethereum_kzg_settings(0)
            .compute_kzg_proof(
                &ckzg_blob,
                &c_kzg::Bytes32::new(standard_challenge_be),
            )
            .unwrap();

        let mut y_be = y.to_bytes();
        y_be.reverse();
        assert_eq!(y_be.as_slice(), ckzg_y.as_slice());
    }

    #[cfg(feature = "host")]
    #[test]
    fn sp1_verify_blob_versioned_hash_against_ckzg() {
        use crate::utils::point_eval;

        // A small synthetic blob envelope (<= N_BLOB_BYTES).
        let mut envelope = Vec::new();
        envelope.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
        envelope.resize(N_BLOB_BYTES, 0);

        let blob = point_eval::to_blob(&envelope);
        let commitment = point_eval::blob_to_kzg_commitment(&blob);
        let versioned_hash = point_eval::get_versioned_hash(&commitment);

        // Build a dummy V7-style challenge digest from the envelope.
        let challenge_digest = {
            use alloy_primitives::keccak256;
            let envelope_hash = keccak256(&envelope);
            keccak256(
                std::iter::empty()
                    .chain(envelope_hash.0)
                    .chain(versioned_hash.0)
                    .collect::<Vec<u8>>(),
            )
        };

        let (proof, _y) = point_eval::get_kzg_proof(&blob, challenge_digest);
        let witness = crate::build_point_eval_witness(
            *commitment.to_bytes(),
            *proof.to_bytes(),
        );

        verify_blob_versioned_hash(
            &envelope,
            versioned_hash,
            challenge_digest,
            &witness,
        );
    }
}
