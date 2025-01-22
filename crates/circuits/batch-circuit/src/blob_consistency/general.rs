pub use bls12_381::Scalar;
use ff::PrimeField;
use alloy_primitives::U256;
use std::sync::LazyLock;
use itertools::Itertools;

use super::BLOB_WIDTH;
/// Base 2 logarithm of BLOB_WIDTH.
const LOG_BLOB_WIDTH: usize = 12;

pub static BLS_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    U256::from_str_radix(&Scalar::MODULUS[2..], 16).expect("BLS_MODULUS from bls crate")
});

pub static ROOTS_OF_UNITY: LazyLock<Vec<Scalar>> = LazyLock::new(|| {
    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = Scalar::from(7);
    let modulus = *BLS_MODULUS;

    let exponent = (modulus - U256::from(1)) / U256::from(4096);
    let root_of_unity = primitive_root_of_unity.pow(exponent.as_limbs());

    let ascending_order: Vec<_> = std::iter::successors(Some(Scalar::one()), |x| Some(*x * root_of_unity))
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
            .zip_eq(coefficients)
            .map(|(root, f)| f * root * (z - root).invert().unwrap())
            .sum::<Scalar>()
        * Scalar::from(blob_width).invert().unwrap()
}

pub fn point_evaluation(coefficients : &[U256; BLOB_WIDTH], challenge_digest: U256) -> (U256, U256) {
    // blob polynomial in evaluation form.
    //
    // also termed P(x)
    let coefficients_as_scalars = coefficients.map(|coeff| Scalar::from_raw(*coeff.as_limbs()));

    let challenge = challenge_digest % *BLS_MODULUS;

    // y = P(z)
    let y = U256::from_le_bytes(
        interpolate(Scalar::from_raw(*challenge.as_limbs()), &coefficients_as_scalars).to_bytes(),
    );
    (challenge, y)

}