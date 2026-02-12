// Copied from https://github.com/axiom-crypto/revm/blob/v75-openvm/crates/precompile/src/bn128.rs under MIT License
use sbv_primitives::types::revm::precompile::PrecompileError;
use std::vec::Vec;

use hex_literal::hex;
use openvm_ecc_guest::{
    AffinePoint,
    algebra::{IntMod, field::FieldExtension},
    weierstrass::{IntrinsicCurve, WeierstrassPoint},
};
use openvm_pairing::{
    PairingCheck,
    bn254::{Bn254, Fp, Fp2, G1Affine, G2Affine, Scalar},
};

/// FQ_LEN specifies the number of bytes needed to represent an
/// Fq element. This is an element in the base field of BN254.
///
/// Note: The base field is used to define G1 and G2 elements.
const FQ_LEN: usize = 32;

/// SCALAR_LEN specifies the number of bytes needed to represent an Fr element.
/// This is an element in the scalar field of BN254.
const SCALAR_LEN: usize = 32;

/// FQ2_LEN specifies the number of bytes needed to represent an
/// Fq^2 element.
///
/// Note: This is the quadratic extension of Fq, and by definition
/// means we need 2 Fq elements.
const FQ2_LEN: usize = 2 * FQ_LEN;

/// G1_LEN specifies the number of bytes needed to represent a G1 element.
///
/// Note: A G1 element contains 2 Fq elements.
const G1_LEN: usize = 2 * FQ_LEN;

const SIX_X_SQUARED: [u64; 2] = [17887900258952609094, 8020209761171036667];

const P_POWER_ENDOMORPHISM_COEFF_0: Fp2 = Fp2::new(
    Fp::from_const_bytes(hex!(
        "3d556f175795e3990c33c3c210c38cb743b159f53cec0b4cf711794f9847b32f"
    )),
    Fp::from_const_bytes(hex!(
        "a2cb0f641cd56516ce9d7c0b1d2aae3294075ad78bcca44b20aeeb6150e5c916"
    )),
);

const P_POWER_ENDOMORPHISM_COEFF_1: Fp2 = Fp2::new(
    Fp::from_const_bytes(hex!(
        "5a13a071460154dc9859c9a9ede0aadbb9f9e2b698c65edcdcf59a4805f33c06"
    )),
    Fp::from_const_bytes(hex!(
        "e3b02326637fd382d25ba28fc97d80212b6f79eca7b504079a0441acbc3cc007"
    )),
);

#[inline]
fn read_fq(input: &[u8]) -> Result<Fp, PrecompileError> {
    if input.len() < FQ_LEN {
        Err(PrecompileError::Bn254FieldPointNotAMember)
    } else {
        Fp::from_be_bytes(&input[..32]).ok_or(PrecompileError::Bn254FieldPointNotAMember)
    }
}

/// Reads a Fq2 (quadratic extension field element) from the input slice.
///
/// Parses two consecutive Fq field elements as the real and imaginary parts
/// of an Fq2 element.
/// The second component is parsed before the first, ie if a we represent an
/// element in Fq2 as (x,y) -- `y` is parsed before `x`
///
/// # Panics
///
/// Panics if the input is not at least 64 bytes long.
#[inline]
fn read_fq2(input: &[u8]) -> Result<Fp2, PrecompileError> {
    let y = read_fq(&input[..FQ_LEN])?;
    let x = read_fq(&input[FQ_LEN..2 * FQ_LEN])?;
    Ok(Fp2::new(x, y))
}

/// Reads a G1 point from the input slice.
///
/// Parses a G1 point from a byte slice by reading two consecutive field elements
/// representing the x and y coordinates.
///
/// # Panics
///
/// Panics if the input is not at least 64 bytes long.
#[inline]
pub(super) fn read_g1_point(input: &[u8]) -> Result<G1Affine, PrecompileError> {
    let px = read_fq(&input[0..FQ_LEN])?;
    let py = read_fq(&input[FQ_LEN..2 * FQ_LEN])?;
    G1Affine::from_xy(px, py).ok_or(PrecompileError::Bn254AffineGFailedToCreate)
}

/// Encodes a G1 point into a byte array.
///
/// Converts a G1 point in Jacobian coordinates to affine coordinates and
/// serializes the x and y coordinates as big-endian byte arrays.
///
/// Note: If the point is the point at infinity, this function returns
/// all zeroes.
#[inline]
pub(super) fn encode_g1_point(point: G1Affine) -> [u8; G1_LEN] {
    let mut output = [0u8; G1_LEN];

    // manually reverse to avoid allocation
    let x_bytes: &[u8] = point.x().as_le_bytes();
    let y_bytes: &[u8] = point.y().as_le_bytes();
    for i in 0..FQ_LEN {
        output[i] = x_bytes[FQ_LEN - 1 - i];
        output[i + FQ_LEN] = y_bytes[FQ_LEN - 1 - i];
    }
    output
}

/// Reads a G2 point from the input slice.
///
/// Parses a G2 point from a byte slice by reading four consecutive Fq field elements
/// representing the two Fq2 coordinates (x and y) of the G2 point.
///
/// # Panics
///
/// Panics if the input is not at least 128 bytes long.
#[inline]
pub(super) fn read_g2_point(input: &[u8]) -> Result<G2Affine, PrecompileError> {
    let ba = read_fq2(&input[0..FQ2_LEN])?;
    let bb = read_fq2(&input[FQ2_LEN..2 * FQ2_LEN])?;

    // [`G2Affine::from_xy`] checks that the point is on the curve, but does not check if the point
    // is in the correct subgroup.
    let point = G2Affine::from_xy(ba, bb).ok_or(PrecompileError::Bn254AffineGFailedToCreate)?;

    // Perform the subgroup check.
    //
    // Implementation is based on section 4.3 of https://eprint.iacr.org/2022/352.pdf.
    //
    // Referenced from the arkworks source code:
    // https://github.com/arkworks-rs/algebra/blob/598a5fbabc1903c7bab6668ef8812bfdf2158723/curves/bn254/src/curves/g2.rs#L60-L68
    let subgroup_check = {
        // 1. Compute [6X^2]P using double-and-add.
        let x_times_point = {
            let mut result = <G2Affine as WeierstrassPoint>::IDENTITY;
            let mut temp = point.clone();
            for limb in SIX_X_SQUARED {
                for bit_idx in 0..64u32 {
                    if (limb >> bit_idx) & 1 == 1 {
                        result.add_assign_impl::<false>(&temp);
                    }
                    temp.double_assign_impl::<false>();
                }
            }
            result
        };

        // 2. Compute psi(P), i.e. "untwist-Frobenius-twist".
        let p_times_point = {
            let psi_x = point.x().frobenius_map(1) * &P_POWER_ENDOMORPHISM_COEFF_0;
            let psi_y = point.y().frobenius_map(1) * &P_POWER_ENDOMORPHISM_COEFF_1;
            G2Affine::from_xy_unchecked(psi_x, psi_y)
        };

        x_times_point.eq(&p_times_point)
    };

    if subgroup_check {
        Ok(point)
    } else {
        Err(PrecompileError::Bn254AffineGFailedToCreate)
    }
}

/// Reads a scalar from the input slice
///
/// Note: The scalar does not need to be canonical.
///
/// # Panics
///
/// If `input.len()` is not equal to [`SCALAR_LEN`].
#[inline]
pub(super) fn read_scalar(input: &[u8]) -> Scalar {
    assert_eq!(
        input.len(),
        SCALAR_LEN,
        "unexpected scalar length. got {}, expected {SCALAR_LEN}",
        input.len()
    );
    Scalar::from_be_bytes_unchecked(input)
}

/// Performs point addition on two G1 points.
#[inline]
pub(super) fn g1_point_add(p1: G1Affine, p2: G1Affine) -> G1Affine {
    p1 + p2
}

/// Performs a G1 scalar multiplication.
#[inline]
pub(super) fn g1_point_mul(p: G1Affine, fr: Scalar) -> G1Affine {
    Bn254::msm(&[fr], &[p])
}

/// pairing_check performs a pairing check on a list of G1 and G2 point pairs and
/// returns true if the result is equal to the identity element.
///
/// Note: If the input is empty, this function returns true.
/// This is different to EIP2537 which disallows the empty input.
#[inline]
pub(super) fn pairing_check(pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileError> {
    let mut g1_points = Vec::with_capacity(pairs.len());
    let mut g2_points = Vec::with_capacity(pairs.len());

    for (g1_bytes, g2_bytes) in pairs {
        let g1_is_zero = g1_bytes.iter().all(|i| *i == 0);
        let g2_is_zero = g2_bytes.iter().all(|i| *i == 0);

        let g1 = read_g1_point(g1_bytes)?;
        let g2 = read_g2_point(g2_bytes)?;

        let (g1x, g1y) = g1.into_coords();
        let (g2x, g2y) = g2.into_coords();

        // Skip pairs where either point is at infinity
        if !g1_is_zero && !g2_is_zero {
            let g1 = AffinePoint::new(g1x, g1y);
            let g2 = AffinePoint::new(g2x, g2y);
            g1_points.push(g1);
            g2_points.push(g2);
        }
    }
    if g1_points.is_empty() {
        return Ok(true);
    }

    Ok(Bn254::pairing_check(&g1_points, &g2_points).is_ok())
}

#[cfg(all(test, feature = "scroll", feature = "host"))]
mod test {
    use super::*;
    use hex_literal::hex;
    use sbv_primitives::{
        B256,
        types::{reth::evm::revm, revm::precompile::PrecompileOutput},
    };

    const G1_IDENTITY: [u8; 64] = [0u8; 64];

    const G2_NON_SUBGROUP: [u8; 128] = hex!(
        "263e2979dbc2fa0e7c73e38ccc6890b84f4191abb9cba88ed36e9e3726f5142d21f24401109878b0eee42d80f405a63c5912bcdfd4aa49ee1e7abf9b41bc3f932173aec93d1b4f8542cbf320eb5b3e7bf495f3a9b3288c9384e91b54c2bff96923c6f9d2be4bdaabb95148a8d78a725db01fc6d66c2bc2b0a964511b778e4238"
    );

    const G1_POINT_1: [u8; 64] = hex!(
        "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41"
    );
    const G1_POINT_2: [u8; 64] = hex!(
        "111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411"
    );

    const G2_POINT_1: [u8; 128] = hex!(
        "209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550"
    );
    const G2_POINT_2: [u8; 128] = hex!(
        "198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"
    );

    #[test]
    fn test_pairing_rejects_non_subgroup_g2() {
        assert!(read_g2_point(&G2_NON_SUBGROUP).is_err());
        assert!(read_g2_point(&G2_POINT_1).is_ok());
        assert!(read_g2_point(&G2_POINT_2).is_ok());
    }

    #[test]
    fn test_pairing_check_non_matching() {
        // 1. pairing check in zkVM.
        let zkvm_res = super::pairing_check(&[(&G1_IDENTITY, &G2_NON_SUBGROUP)]);

        // 2. pairing check in revm.
        let revm_res = {
            let provider = sbv_primitives::types::revm::ScrollPrecompileProvider::new_with_spec(
                sbv_primitives::types::revm::SpecId::GALILEO,
            );
            let precompile = provider
                .precompiles()
                .get(&revm::precompile::bn254::pair::ADDRESS)
                .expect("should be ok");
            let input = std::iter::empty()
                .chain(G1_IDENTITY)
                .chain(G2_NON_SUBGROUP)
                .collect::<Vec<u8>>();
            precompile.execute(input.as_slice(), 500_000)
        };

        // G1 is identity element, however G2 is point on curve that is *not* in subgroup.
        //
        // Initial decoding of input bytes should fail in the execution client.
        //
        // However, zkVM skips the check for *point in subgroup* and hence pairing check output is
        // 1, due to the fact that G1 is identity element.
        assert_eq!(zkvm_res, Err(PrecompileError::Bn254AffineGFailedToCreate));
        assert_eq!(revm_res, Err(PrecompileError::Bn254AffineGFailedToCreate));
    }

    #[test]
    fn test_pairing_check_matching() {
        // 1. pairing check in zkVM.
        let zkvm_res =
            super::pairing_check(&[(&G1_POINT_1, &G2_POINT_1), (&G1_POINT_2, &G2_POINT_2)]);

        // 2. pairing check in revm.
        let revm_res = {
            let provider = sbv_primitives::types::revm::ScrollPrecompileProvider::new_with_spec(
                sbv_primitives::types::revm::SpecId::GALILEO,
            );
            let precompile = provider
                .precompiles()
                .get(&revm::precompile::bn254::pair::ADDRESS)
                .expect("should be ok");
            let input = std::iter::empty()
                .chain(G1_POINT_1)
                .chain(G2_POINT_1)
                .chain(G1_POINT_2)
                .chain(G2_POINT_2)
                .collect::<Vec<u8>>();
            precompile.execute(input.as_slice(), 500_000)
        };

        // Here we have both G1 and G2 points valid, i.e. on curve and in the subgroup.
        //
        // We expect zkVM and revm impls to compute matching results.
        assert_eq!(zkvm_res.ok(), Some(true));
        let Some(PrecompileOutput {
            gas_used: _gas_used,
            bytes,
            reverted: _reverted,
        }) = revm_res.ok()
        else {
            panic!("revm pairing check should have succeeded");
        };
        assert_eq!(bytes, B256::with_last_byte(1).to_vec());
    }

    #[test]
    fn test_const_values() {
        use ark_serialize::CanonicalSerialize;

        // Refer arkworks definitions:
        // - https://github.com/arkworks-rs/algebra/blob/598a5fbabc1903c7bab6668ef8812bfdf2158723/curves/bn254/src/curves/g2.rs#L123-L127
        // - https://github.com/arkworks-rs/algebra/blob/598a5fbabc1903c7bab6668ef8812bfdf2158723/curves/bn254/src/curves/g2.rs#L129-L133
        let ark_coeff_0 = ark_bn254::Fq2::new(
            ark_ff::MontFp!(
                "21575463638280843010398324269430826099269044274347216827212613867836435027261"
            ),
            ark_ff::MontFp!(
                "10307601595873709700152284273816112264069230130616436755625194854815875713954"
            ),
        );
        let ark_coeff_1 = ark_bn254::Fq2::new(
            ark_ff::MontFp!(
                "2821565182194536844548159561693502659359617185244120367078079554186484126554"
            ),
            ark_ff::MontFp!(
                "3505843767911556378687030309984248845540243509899259641013678093033130930403"
            ),
        );
        let mut coeff_0_bytes = Vec::with_capacity(64);
        ark_coeff_0
            .serialize_uncompressed(&mut coeff_0_bytes)
            .expect("should not fail");
        let mut coeff_1_bytes = Vec::with_capacity(64);
        ark_coeff_1
            .serialize_uncompressed(&mut coeff_1_bytes)
            .expect("should not fail");
        assert_eq!(coeff_0_bytes, P_POWER_ENDOMORPHISM_COEFF_0.to_bytes());
        assert_eq!(coeff_1_bytes, P_POWER_ENDOMORPHISM_COEFF_1.to_bytes());
    }
}
