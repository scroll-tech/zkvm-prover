use std::ops::{AddAssign, MulAssign, Neg};
use std::sync::LazyLock;

use algebra::{Field, IntMod};
use alloy_primitives::U256;
use halo2curves_axiom::bls12_381::G2Affine as Bls12_381_G2;
use itertools::Itertools;
use openvm_ecc_guest::{AffinePoint, CyclicGroup, msm, weierstrass::WeierstrassPoint};
use openvm_pairing::bls12_381::{Bls12_381, G1Affine, G2Affine, Scalar};
use openvm_pairing_guest::{algebra, pairing::PairingCheck};

use super::types::ToIntrinsic;
use crate::blob_consistency::constants::KZG_G2_SETUP_BYTES;

use super::{BLOB_WIDTH, LOG_BLOB_WIDTH};

static BLS_MODULUS: LazyLock<U256> = LazyLock::new(|| U256::from_le_bytes(Scalar::MODULUS));

static ROOTS_OF_UNITY: LazyLock<Vec<Scalar>> = LazyLock::new(|| {
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = Scalar::from_u8(7);
    let modulus = *BLS_MODULUS;

    let exponent = (modulus - U256::from(1)) / U256::from(4096);
    let root_of_unity = pow_bytes(&primitive_root_of_unity, &exponent.to_be_bytes::<32>());

    let mut ascending_order: Vec<Scalar> = Vec::new();
    ascending_order.resize(BLOB_WIDTH, <Scalar as IntMod>::ZERO);
    ascending_order[0] = <Scalar as IntMod>::ONE; // First element should be 1

    for i in 1..BLOB_WIDTH {
        let (left, right) = ascending_order.split_at_mut(i);
        right[0].add_assign(&left[left.len() - 1]);
        right[0].mul_assign(&root_of_unity);
    }

    (0..BLOB_WIDTH)
        .map(|i| {
            let j = u16::try_from(i).unwrap().reverse_bits() >> (16 - LOG_BLOB_WIDTH);
            ascending_order[usize::from(j)].clone()
        })
        .collect()
});

static G2_GENERATOR: LazyLock<G2Affine> =
    LazyLock::new(|| Bls12_381_G2::generator().to_intrinsic());

static KZG_G2_SETUP: LazyLock<G2Affine> = LazyLock::new(|| {
    Bls12_381_G2::from_uncompressed_unchecked_be(&KZG_G2_SETUP_BYTES)
        .expect("kzg G2 setup bytes")
        .to_intrinsic()
});

/// The version for KZG as per EIP-4844.
const VERSIONED_HASH_VERSION_KZG: u8 = 1;

/// Verify KZG `proof` that `P(z) == y` where `P` is the EIP-4844 blob polynomial in its evaluation
/// form, and `commitment` is the KZG commitment to the polynomial `P`.
///
/// We use [`openvm_pairing_guest`] extension to implement this in guest program.
pub fn verify_kzg_proof(z: Scalar, y: Scalar, commitment: G1Affine, proof: G1Affine) -> bool {
    let proof_q = G1Affine::from_xy_nonidentity(proof.x().clone(), proof.y().clone())
        .expect("kzg proof not G1 identity");
    let p_minus_y = G1Affine::from_xy_nonidentity(commitment.x().clone(), commitment.y().clone())
        .expect("kzg commitment not G1 identity")
        - msm(&[y], std::slice::from_ref(&G1Affine::GENERATOR));
    let g2_generator: &G2Affine = &G2_GENERATOR;
    let x_minus_z = msm(&[z], std::slice::from_ref(g2_generator)) - KZG_G2_SETUP.clone();

    let p0_proof = AffinePoint::new(proof_q.x().clone(), proof_q.y().clone());
    let q0 = AffinePoint::new(p_minus_y.x().clone(), p_minus_y.y().clone());
    let p1 = AffinePoint::new(x_minus_z.x().clone(), x_minus_z.y().clone());
    let q1 = AffinePoint::new(G2_GENERATOR.x().clone(), G2_GENERATOR.y().clone());

    Bls12_381::pairing_check(&[q0, p0_proof], &[q1, p1]).is_ok()
}

/// Request to verify a single KZG proof.
#[derive(Clone)]
pub struct VerifyKzg {
    /// Random point of evaluation.
    pub z: Scalar,
    /// Evaluation of the blob polynomial at `z`.
    pub y: Scalar,
    /// KZG commitment to the polynomial.
    pub commitment: G1Affine,
    /// KZG proof.
    pub proof: G1Affine,
}

/// Alias for request to verify a batch of KZG proofs.
pub type BatchVerifyKzg = Vec<VerifyKzg>;

/// Domain separator for the random challenge in batch KZG verification.
/// Matches the Ethereum consensus spec constant RANDOM_CHALLENGE_KZG_BATCH_DOMAIN.
const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &[u8] = b"RCKZGBATCH___V1_";

/// Verify a batch of KZG proofs efficiently using random linear combination.
///
/// Implements the [`verify_kzg_proof_batch`] algorithm from the Ethereum consensus specs:
/// <https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#verify_kzg_proof_batch>
///
/// Instead of running `n` independent pairing checks, this aggregates all proofs into
/// a single pairing check using a random challenge `r`, achieving ~n× speedup.
pub fn verify_kzg_proof_batch(input: &BatchVerifyKzg) -> bool {
    if input.is_empty() {
        return true;
    }

    // For a single proof, just use the direct verification.
    if input.len() == 1 {
        return verify_kzg_proof(
            input[0].z.clone(),
            input[0].y.clone(),
            input[0].commitment.clone(),
            input[0].proof.clone(),
        );
    }

    // 1. Compute random challenge `r` from a transcript of all inputs.
    //    r = hash_to_bls_field(domain || degree || n || commitment_0 || z_0 || y_0 || proof_0 || ...)
    let r = {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);
        transcript.extend_from_slice(&(BLOB_WIDTH as u64).to_be_bytes());
        transcript.extend_from_slice(&(input.len() as u64).to_be_bytes());

        for item in input {
            // Commitment (compressed G1 = 48 bytes) — use raw x,y coords for transcript
            transcript.extend_from_slice(item.commitment.x().as_le_bytes());
            transcript.extend_from_slice(item.commitment.y().as_le_bytes());
            // z (scalar = 32 bytes)
            transcript.extend_from_slice(item.z.as_le_bytes());
            // y (scalar = 32 bytes)
            transcript.extend_from_slice(item.y.as_le_bytes());
            // Proof (compressed G1 = 48 bytes) — use raw x,y coords
            transcript.extend_from_slice(item.proof.x().as_le_bytes());
            transcript.extend_from_slice(item.proof.y().as_le_bytes());
        }

        // Hash transcript to a BLS scalar field element
        let hash = openvm_sha2::sha256(&transcript);
        // Reduce hash modulo BLS scalar field order
        let hash_u256 = U256::from_be_bytes(hash);
        let reduced = hash_u256 % *BLS_MODULUS;
        Scalar::from_le_bytes_unchecked(reduced.as_le_slice())
    };

    // 2. Compute powers of r: [1, r, r², ..., r^(n-1)]
    let n = input.len();
    let mut r_powers = Vec::with_capacity(n);
    r_powers.push(<Scalar as IntMod>::ONE);
    for i in 1..n {
        let prev = r_powers[i - 1].clone();
        r_powers.push(&prev * &r);
    }

    // 3. Compute proof_lincomb = Σ r^i * proof_i
    let proof_points: Vec<G1Affine> = input.iter().map(|item| item.proof.clone()).collect();
    let proof_lincomb = msm(&r_powers, &proof_points);

    // 4. Compute proof_z_lincomb = Σ r^i * z_i * proof_i
    let rz_scalars: Vec<Scalar> = r_powers
        .iter()
        .zip(input.iter())
        .map(|(ri, item)| ri * &item.z)
        .collect();
    let proof_z_lincomb = msm(&rz_scalars, &proof_points);

    // 5. Compute C_minus_y_lincomb = Σ r^i * (commitment_i - y_i * G1)
    let c_minus_ys: Vec<G1Affine> = input
        .iter()
        .map(|item| {
            let y_g = msm(
                std::slice::from_ref(&item.y),
                std::slice::from_ref(&G1Affine::GENERATOR),
            );
            item.commitment.clone() - y_g
        })
        .collect();
    let c_minus_y_lincomb = msm(&r_powers, &c_minus_ys);

    // 6. Final pairing check:
    //    e(proof_lincomb, -KZG_G2_SETUP) * e(C_minus_y_lincomb + proof_z_lincomb, G2_GEN) == 1
    //
    //    Equivalently: pairing_check([proof_lincomb, C_minus_y_lincomb + proof_z_lincomb],
    //                                [-KZG_G2_SETUP, G2_GEN]) == ok
    let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

    let p0 = AffinePoint::new(proof_lincomb.x().clone(), proof_lincomb.y().clone());
    let p1 = AffinePoint::new(rhs_g1.x().clone(), rhs_g1.y().clone());

    // Negate KZG_G2_SETUP for the pairing check
    let neg_kzg_g2 = {
        let kzg = KZG_G2_SETUP.clone();
        // Negate y-coordinate of G2 point
        let neg_y = kzg.y().neg();
        AffinePoint::new(kzg.x().clone(), neg_y)
    };
    let q0 = neg_kzg_g2;
    let q1 = AffinePoint::new(G2_GENERATOR.x().clone(), G2_GENERATOR.y().clone());

    Bls12_381::pairing_check(&[p0, p1], &[q0, q1]).is_ok()
}

/// Given the coefficients of the blob polynomial, evaluate the polynomial at the given challenge.
///
/// The challenge provided is actually a challenge digest (32-bytes) that should be modded with the
/// BLS12-381 scalar modulus, to get the actual challenge scalar.
pub fn point_evaluation(
    coefficients: &[U256; BLOB_WIDTH],
    challenge_digest: U256,
) -> (Scalar, Scalar) {
    // blob polynomial in evaluation form.
    //
    // also termed P(x)
    let coefficients_as_scalars =
        coefficients.map(|coeff| Scalar::from_le_bytes_unchecked(coeff.as_le_slice()));

    let challenge = challenge_digest % *BLS_MODULUS;
    let challenge = Scalar::from_le_bytes_unchecked(challenge.as_le_slice());

    // y = P(z)
    let evaluation = interpolate(&challenge, &coefficients_as_scalars);

    (challenge, evaluation)
}

/// Compute the versioned hash based on KZG scheme in EIP-4844.
///
/// We use the [`openvm_sha256_guest`] extension to compute the SHA-256 digest.
pub fn kzg_to_versioned_hash(kzg_commitment: &[u8]) -> [u8; 32] {
    let mut hash = openvm_sha2::sha256(kzg_commitment);
    hash[0] = VERSIONED_HASH_VERSION_KZG;
    hash
}

// picked from ExpBytes trait, some compilation issue (infinity recursion) raised
// from the exp_bytes entry and can not resolved it currently
fn pow_bytes(base: &Scalar, bytes_be: &[u8]) -> Scalar {
    let x = base.clone();

    let mut res = <Scalar as IntMod>::ONE;

    let x_sq = &x * &x;
    let ops = [x.clone(), x_sq.clone(), &x_sq * &x];

    for &b in bytes_be.iter() {
        let mut mask = 0xc0;
        for j in 0..4 {
            res = &res * &res * &res * &res;
            let c = (b & mask) >> (6 - 2 * j);
            if c != 0 {
                res *= &ops[(c - 1) as usize];
            }
            mask >>= 2;
        }
    }
    res
}

fn interpolate(z: &Scalar, coefficients: &[Scalar; BLOB_WIDTH]) -> Scalar {
    let blob_width = u64::try_from(BLOB_WIDTH).unwrap();
    (pow_bytes(z, &blob_width.to_be_bytes()) - <Scalar as IntMod>::ONE)
        * ROOTS_OF_UNITY
            .iter()
            .zip_eq(coefficients)
            .map(|(root, f)| f * root * (z.clone() - root).invert())
            .sum::<Scalar>()
        * Scalar::from_u64(blob_width).invert()
}

#[cfg(test)]
mod test {
    use super::*;

    use halo2curves_axiom::bls12_381::G1Affine as Bls12_381_G1;

    #[test]
    fn test_kzg_compute_proof_verify() {
        use c_kzg::{Blob, Bytes32, Bytes48};
        // Initialize the blob with a single field element
        let settings = c_kzg::ethereum_kzg_settings(0);
        let field_elem =
            Bytes32::from_hex("69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13")
                .unwrap();
        let blob = Blob::new({
            let mut bt = [0u8; 131072];
            bt[..32].copy_from_slice(field_elem.as_ref());
            bt
        });
        let commitment = settings.blob_to_kzg_commitment(&blob).unwrap();

        let input_val =
            Bytes32::from_hex("03ea4fb841b4f9e01aa917c5e40dbd67efb4b8d4d9052069595f0647feba320d")
                .unwrap();

        let expected_proof_byte48 = Bytes48::from_hex("b21f8f9b85e52fd9c4a6d4fb4e9a27ebdc5a09c3f5ca17f6bcd85c26f04953b0e6925607aaebed1087e5cc2fe4b2b356").unwrap();
        let (proof, y) = settings.compute_kzg_proof(&blob, &input_val).unwrap();

        // assert_eq!(Bytes32::from_hex("69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13").unwrap(), y);
        assert_eq!(expected_proof_byte48, proof.to_bytes());

        let ret = settings
            .verify_kzg_proof(&commitment.to_bytes(), &input_val, &y, &proof.to_bytes())
            .unwrap();
        assert!(ret, "failed at sanity check verify");

        let z = Scalar::from_be_bytes_unchecked(input_val.as_ref());
        let y = Scalar::from_be_bytes_unchecked(y.as_ref());
        let commitment = Bls12_381_G1::from_compressed_be(commitment.to_bytes().as_ref())
            .unwrap()
            .to_intrinsic();
        let proof = Bls12_381_G1::from_compressed_be(proof.to_bytes().as_ref())
            .unwrap()
            .to_intrinsic();
        let proof_ok = verify_kzg_proof(z, y, commitment, proof);
        assert!(proof_ok, "verify failed");
    }

    #[test]
    fn test_kzg_batch_verify_single() {
        use c_kzg::{Blob, Bytes32, Bytes48};
        let settings = c_kzg::ethereum_kzg_settings(0);

        // Create a blob and compute a proof
        let field_elem =
            Bytes32::from_hex("69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13")
                .unwrap();
        let blob = Blob::new({
            let mut bt = [0u8; 131072];
            bt[..32].copy_from_slice(field_elem.as_ref());
            bt
        });
        let commitment = settings.blob_to_kzg_commitment(&blob).unwrap();

        let input_val =
            Bytes32::from_hex("03ea4fb841b4f9e01aa917c5e40dbd67efb4b8d4d9052069595f0647feba320d")
                .unwrap();
        let (proof, y) = settings.compute_kzg_proof(&blob, &input_val).unwrap();

        let z = Scalar::from_be_bytes_unchecked(input_val.as_ref());
        let y = Scalar::from_be_bytes_unchecked(y.as_ref());
        let commitment = Bls12_381_G1::from_compressed_be(commitment.to_bytes().as_ref())
            .unwrap()
            .to_intrinsic();
        let proof = Bls12_381_G1::from_compressed_be(proof.to_bytes().as_ref())
            .unwrap()
            .to_intrinsic();

        // Batch verify with a single proof should match individual verification
        let batch_ok = verify_kzg_proof_batch(&vec![VerifyKzg {
            z: z.clone(),
            y: y.clone(),
            commitment: commitment.clone(),
            proof: proof.clone(),
        }]);
        assert!(batch_ok, "batch verify with single proof failed");
    }

    #[test]
    fn test_kzg_batch_verify_multiple() {
        use c_kzg::{Blob, Bytes32};
        let settings = c_kzg::ethereum_kzg_settings(0);

        // Create two different blobs and proofs
        let mut proofs = Vec::new();
        for (field_hex, challenge_hex) in [
            (
                "69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13",
                "03ea4fb841b4f9e01aa917c5e40dbd67efb4b8d4d9052069595f0647feba320d",
            ),
            (
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567800000000",
                "0bea4fb841b4f9e01aa917c5e40dbd67efb4b8d4d9052069595f064700000000",
            ),
        ] {
            let field_elem = Bytes32::from_hex(field_hex).unwrap();
            let blob = Blob::new({
                let mut bt = [0u8; 131072];
                bt[..32].copy_from_slice(field_elem.as_ref());
                bt
            });
            let commitment = settings.blob_to_kzg_commitment(&blob).unwrap();
            let input_val = Bytes32::from_hex(challenge_hex).unwrap();
            let (proof, y) = settings.compute_kzg_proof(&blob, &input_val).unwrap();

            // Verify individually first
            let ret = settings
                .verify_kzg_proof(&commitment.to_bytes(), &input_val, &y, &proof.to_bytes())
                .unwrap();
            assert!(ret, "individual c-kzg verify failed");

            let z = Scalar::from_be_bytes_unchecked(input_val.as_ref());
            let y = Scalar::from_be_bytes_unchecked(y.as_ref());
            let commitment = Bls12_381_G1::from_compressed_be(commitment.to_bytes().as_ref())
                .unwrap()
                .to_intrinsic();
            let proof = Bls12_381_G1::from_compressed_be(proof.to_bytes().as_ref())
                .unwrap()
                .to_intrinsic();

            proofs.push(VerifyKzg { z, y, commitment, proof });
        }

        // Batch verify both proofs
        let batch_ok = verify_kzg_proof_batch(&proofs);
        assert!(batch_ok, "batch verify with multiple proofs failed");
    }

    #[test]
    fn test_kzg_batch_verify_empty() {
        assert!(verify_kzg_proof_batch(&vec![]), "empty batch should return true");
    }
}
