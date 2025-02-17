use core::{clone::Clone, convert::TryFrom};
use std::sync::LazyLock;

use algebra::{Field, IntMod};
use alloy_primitives::U256;
use itertools::Itertools;
use openvm_ecc_guest::{msm, weierstrass::WeierstrassPoint, AffinePoint, CyclicGroup, Group};
use openvm_pairing_guest::{
    algebra, bls12_381::{Bls12_381, Fp, Fp2, Scalar, G1Affine, G2Affine},
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

use openvm_ecc_guest::halo2curves::bls12_381::{
    Fq as HL2Fp,
    G2Affine as Halo2G2Affine,
};

fn convert_bls12381_halo2_fq_to_fp(x: HL2Fp) -> Fp {
    let bytes = x.to_bytes();
    Fp::from_le_bytes(&bytes)
}

fn convert_bls12381_halo2_g2_to_g2(p: Halo2G2Affine) -> G2Affine {
    let halo2_x = p.x;
    let halo2_y = p.y;

    let x = Fp2::new(
        convert_bls12381_halo2_fq_to_fp(halo2_x.c0),
        convert_bls12381_halo2_fq_to_fp(halo2_x.c1),
    );

    let y = Fp2::new(
        convert_bls12381_halo2_fq_to_fp(halo2_y.c0),
        convert_bls12381_halo2_fq_to_fp(halo2_y.c1),
    );

    G2Affine::from_xy_unchecked(x, y)
}

static G2_GENERATOR: LazyLock<G2Affine> = LazyLock::new(|| convert_bls12381_halo2_g2_to_g2(Halo2G2Affine::generator()));

static KZG_G2_SETUP: LazyLock<G2Affine> = LazyLock::new(|| {

    const KZG_G2_SETUP_BYTES: [u8; 96] = [
        0xb5, 0xbf, 0xd7, 0xdd, 0x8c, 0xde, 0xb1, 0x28, 
        0x84, 0x3b, 0xc2, 0x87, 0x23, 0x0a, 0xf3, 0x89, 
        0x26, 0x18, 0x70, 0x75, 0xcb, 0xfb, 0xef, 0xaa, 
        0x10, 0x09, 0xa2, 0xce, 0x61, 0x5a, 0xc5, 0x3d, 
        0x29, 0x14, 0xe5, 0x87, 0x0c, 0xb4, 0x52, 0xd2, 
        0xaf, 0xaa, 0xab, 0x24, 0xf3, 0x49, 0x9f, 0x72, 
        0x18, 0x5c, 0xbf, 0xee, 0x53, 0x49, 0x27, 0x14, 
        0x73, 0x44, 0x29, 0xb7, 0xb3, 0x86, 0x08, 0xe2, 
        0x39, 0x26, 0xc9, 0x11, 0xcc, 0xec, 0xea, 0xc9, 
        0xa3, 0x68, 0x51, 0x47, 0x7b, 0xa4, 0xc6, 0x0b, 
        0x08, 0x70, 0x41, 0xde, 0x62, 0x10, 0x00, 0xed, 
        0xc9, 0x8e, 0xda, 0xda, 0x20, 0xc1, 0xde, 0xf2,
    ];

    convert_bls12381_halo2_g2_to_g2(Halo2G2Affine::from_compressed_be(&KZG_G2_SETUP_BYTES).unwrap())
});

// for scalar, use `as_le_bytes` in IntMod for mul by_le argument
fn group_mul<C: Group>(point: C, by_le: &[u8]) -> C {

    let mut acc = C::IDENTITY.clone();

    // This is a simple double-and-add implementation of point
    // multiplication, moving from most significant to least
    // significant bit of the scalar.
    //
    // We skip the leading bit because it's always unset for Fq
    // elements.
    for bit in by_le
        .iter()
        .rev()
        .flat_map(|byte| (0..8).rev().map(move |i| (byte >> i) & 1u8))
        .skip(1)
    {
        acc = acc.double();
        if bit == 1u8 {
            acc.add_assign(point.clone());
        }
    }

    acc

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

fn interpolate(z: Scalar, coefficients: &[Scalar; BLOB_WIDTH]) -> Scalar {
    let blob_width = u64::try_from(BLOB_WIDTH).unwrap();
    (pow_bytes(&z, &blob_width.to_be_bytes()) - <Scalar as IntMod>::ONE)
        * ROOTS_OF_UNITY
            .iter()
            .zip_eq(coefficients)
            .map(|(root, f)| f * root * (z.clone() - root).invert())
            .sum::<Scalar>()
        * Scalar::from_u64(blob_width).invert()
}

pub fn verify_kzg(z: Scalar, y: Scalar, commitment: (Fp, Fp), proof: (Fp, Fp)) -> bool {
    
    let proof_q = G1Affine::from_xy_nonidentity(proof.0, proof.1).unwrap();
    let y_minus_p = msm(&[y], &[G1Affine::GENERATOR.clone()]) - G1Affine::from_xy_nonidentity(commitment.0, commitment.1).unwrap();
    let x_minus_z = KZG_G2_SETUP.clone() -msm(&[z], &[G2_GENERATOR.clone()]);
    
    let p0_proof = AffinePoint::new(
        proof_q.x().clone(),
        proof_q.y().clone(),
    );
    let q0 = AffinePoint::new(
        y_minus_p.x().clone(),
        y_minus_p.y().clone(),
    );
    let p1 = AffinePoint::new(
        x_minus_z.x().clone(),
        x_minus_z.y().clone(),
    );
    let q1 = AffinePoint::new(
        <G2Affine as Group>::IDENTITY.x().clone(),
        <G2Affine as Group>::IDENTITY.y().clone(),
    );

    Bls12_381::pairing_check(
        &[p0_proof, q0], 
        &[p1, q1],
    ).is_ok()
}

pub fn point_evaluation(coefficients: &[U256; BLOB_WIDTH], challenge_digest: U256) -> (U256, U256) {
    // blob polynomial in evaluation form.
    //
    // also termed P(x)
    let coefficients_as_scalars =
        coefficients.map(|coeff| Scalar::from_le_bytes(coeff.as_le_slice()));

    let challenge = challenge_digest % *BLS_MODULUS;

    // y = P(z)
    let y = U256::from_le_slice(
        interpolate(
            Scalar::from_le_bytes(challenge.as_le_slice()),
            &coefficients_as_scalars,
        )
        .as_le_bytes(),
    );

    (challenge, y)
}

