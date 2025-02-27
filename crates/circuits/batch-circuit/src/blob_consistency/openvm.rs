use std::sync::LazyLock;

use algebra::{Field, IntMod};
use alloy_primitives::U256;
use itertools::Itertools;
use openvm_ecc_guest::{
    AffinePoint, CyclicGroup,
    halo2curves::bls12_381::{
        Fq as Bls12_381_Fq, G1Affine as Bls12_381_G1, G2Affine as Bls12_381_G2,
    },
    msm,
    weierstrass::WeierstrassPoint,
};
use openvm_pairing_guest::{
    algebra,
    bls12_381::{Bls12_381, Fp, Fp2, G1Affine, G2Affine, Scalar},
    pairing::PairingCheck,
};

use super::{BLOB_WIDTH, LOG_BLOB_WIDTH};

static BLS_MODULUS: LazyLock<U256> = LazyLock::new(|| U256::from_le_bytes(Scalar::MODULUS));

static ROOTS_OF_UNITY: LazyLock<Vec<Scalar>> = LazyLock::new(|| {
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = Scalar::from_u8(7);
    let modulus = *BLS_MODULUS;

    let exponent = (modulus - U256::from(1)) / U256::from(4096);
    let root_of_unity = pow_bytes(&primitive_root_of_unity, &exponent.to_be_bytes::<32>());

    let ascending_order: Vec<_> = std::iter::successors(Some(<Scalar as IntMod>::ONE), |x| {
        Some(x.clone() * root_of_unity.clone())
    })
    .take(BLOB_WIDTH)
    .collect();

    (0..BLOB_WIDTH)
        .map(|i| {
            let j = u16::try_from(i).unwrap().reverse_bits() >> (16 - LOG_BLOB_WIDTH);
            ascending_order[usize::from(j)].clone()
        })
        .collect()
});

static G2_GENERATOR: LazyLock<G2Affine> = LazyLock::new(|| Bls12_381_G2::generator().convert());

static KZG_G2_SETUP: LazyLock<G2Affine> = LazyLock::new(|| {
    // b5bfd7dd8cdeb128
    // 843bc287230af389
    // 26187075cbfbefa8
    // 1009a2ce615ac53d
    // 2914e5870cb452d2
    // afaaab24f3499f72
    // 185cbfee53492714
    // 734429b7b38608e2
    // 3926c911cceceac9
    // a36851477ba4c60b
    // 087041de621000ed
    // c98edada20c1def2
    const KZG_G2_SETUP_BYTES: [u8; 96] = [
        0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28, 0x84, 0x3b, 0xc2, 0x87, 0x23, 0x0a, 0xf3,
        0x89, 0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xa8, 0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a,
        0xc5, 0x3d, 0x29, 0x14, 0xe5, 0x87, 0x0c, 0xb4, 0x52, 0xd2, 0xaf, 0xaa, 0xab, 0x24, 0xf3,
        0x49, 0x9f, 0x72, 0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14, 0x73, 0x44, 0x29, 0xb7,
        0xb3, 0x86, 0x08, 0xe2, 0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9, 0xa3, 0x68, 0x51,
        0x47, 0x7b, 0xa4, 0xc6, 0x0b, 0x08, 0x70, 0x41, 0xde, 0x62, 0x10, 0x00, 0xed, 0xc9, 0x8e,
        0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2,
    ];

    Bls12_381_G2::from_compressed_be(&KZG_G2_SETUP_BYTES)
        .expect("kzg G2 setup bytes")
        .convert()
});

/// The version for KZG as per EIP-4844.
const VERSIONED_HASH_VERSION_KZG: u8 = 1;

/// Helper trait that provides functionality to convert types from [`openvm_ecc_guest`] to
/// [`openvm_pairing_guest`].
pub trait EccToPairing {
    /// The desired converted type from [`openvm_pairing_guest`].
    type PairingType;

    /// Convert the given type from [`openvm_ecc_guest`] to the desired type from
    /// [`openvm_pairing_guest`].
    fn convert(&self) -> Self::PairingType;
}

impl EccToPairing for Bls12_381_Fq {
    type PairingType = Fp;

    fn convert(&self) -> Self::PairingType {
        let bytes = self.to_bytes();
        Fp::from_le_bytes(&bytes)
    }
}

impl EccToPairing for Bls12_381_G1 {
    type PairingType = G1Affine;

    fn convert(&self) -> Self::PairingType {
        G1Affine::from_xy_unchecked(self.x.convert(), self.y.convert())
    }
}

impl EccToPairing for Bls12_381_G2 {
    type PairingType = G2Affine;

    fn convert(&self) -> Self::PairingType {
        G2Affine::from_xy_unchecked(
            Fp2::new(self.x.c0.convert(), self.x.c1.convert()),
            Fp2::new(self.y.c0.convert(), self.y.c1.convert()),
        )
    }
}

/// Verify KZG `proof` that `P(z) == y` where `P` is the EIP-4844 blob polynomial in its evaluation
/// form, and `commitment` is the KZG commitment to the polynomial `P`.
///
/// We use [`openvm_pairing_guest`] extension to implement this in guest program.
pub fn verify_kzg_proof(z: Scalar, y: Scalar, commitment: G1Affine, proof: G1Affine) -> bool {
    let proof_q = G1Affine::from_xy_nonidentity(proof.x().clone(), proof.y().clone())
        .expect("kzg proof not G1 identity");
    let p_minus_y = G1Affine::from_xy_nonidentity(commitment.x().clone(), commitment.y().clone())
        .expect("kzg commitment not G1 identity")
        - msm(&[y], &[G1Affine::GENERATOR.clone()]);
    let x_minus_z = msm(&[z], &[G2_GENERATOR.clone()]) - KZG_G2_SETUP.clone();

    let p0_proof = AffinePoint::new(proof_q.x().clone(), proof_q.y().clone());
    let q0 = AffinePoint::new(p_minus_y.x().clone(), p_minus_y.y().clone());
    let p1 = AffinePoint::new(x_minus_z.x().clone(), x_minus_z.y().clone());
    let q1 = AffinePoint::new(G2_GENERATOR.x().clone(), G2_GENERATOR.y().clone());

    Bls12_381::pairing_check(&[q0, p0_proof], &[q1, p1]).is_ok()
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
        coefficients.map(|coeff| Scalar::from_le_bytes(coeff.as_le_slice()));

    let challenge = challenge_digest % *BLS_MODULUS;
    let challenge = Scalar::from_le_bytes(challenge.as_le_slice());

    // y = P(z)
    let evaluation = interpolate(&challenge, &coefficients_as_scalars);

    (challenge, evaluation)
}

/// Compute the versioned hash based on KZG scheme in EIP-4844.
///
/// We use the [`openvm_sha256_guest`] extension to compute the SHA-256 digest.
pub fn kzg_to_versioned_hash(kzg_commitment: &[u8]) -> [u8; 32] {
    let mut hash = openvm_sha256_guest::sha256(kzg_commitment);
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

    #[test]
    fn test_kzg_compute_proof_verify() {
        use c_kzg::{Blob, Bytes32, Bytes48};
        // Initialize the blob with a single field element
        let field_elem =
            Bytes32::from_hex("69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13")
                .unwrap();
        let blob = Blob::new({
            let mut bt = [0u8; 131072];
            bt[..32].copy_from_slice(field_elem.as_ref());
            bt
        });
        let commitment =
            c_kzg::KzgCommitment::blob_to_kzg_commitment(&blob, c_kzg::ethereum_kzg_settings())
                .unwrap();

        let input_val =
            Bytes32::from_hex("03ea4fb841b4f9e01aa917c5e40dbd67efb4b8d4d9052069595f0647feba320d")
                .unwrap();

        let expected_proof_byte48 = Bytes48::from_hex("b21f8f9b85e52fd9c4a6d4fb4e9a27ebdc5a09c3f5ca17f6bcd85c26f04953b0e6925607aaebed1087e5cc2fe4b2b356").unwrap();
        let (proof, y) =
            c_kzg::KzgProof::compute_kzg_proof(&blob, &input_val, c_kzg::ethereum_kzg_settings())
                .unwrap();

        // assert_eq!(Bytes32::from_hex("69386e69dbae0357b399b8d645a57a3062dfbe00bd8e97170b9bdd6bc6168a13").unwrap(), y);
        assert_eq!(expected_proof_byte48, proof.to_bytes());

        let ret = c_kzg::KzgProof::verify_kzg_proof(
            &commitment.to_bytes(),
            &input_val,
            &y,
            &proof.to_bytes(),
            c_kzg::ethereum_kzg_settings(),
        )
        .unwrap();
        assert!(ret, "failed at sanity check verify");

        let z = Scalar::from_be_bytes(input_val.as_ref());
        let y = Scalar::from_be_bytes(y.as_ref());
        let commitment = Bls12_381_G1::from_compressed_be(commitment.to_bytes().as_ref())
            .unwrap()
            .convert();
        let proof = Bls12_381_G1::from_compressed_be(proof.to_bytes().as_ref())
            .unwrap()
            .convert();
        let proof_ok = verify_kzg_proof(z, y, commitment, proof);
        assert!(proof_ok, "verify failed");
    }
}
