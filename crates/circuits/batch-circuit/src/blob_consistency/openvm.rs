
pub use openvm_pairing_guest::bls12_381::Scalar;
use openvm_pairing_guest::algebra;
use algebra::{ExpBytes, Field};
use alloy_primitives::U256;
use std::sync::LazyLock;
use itertools::Itertools;

use super::BLOB_WIDTH;
/// Base 2 logarithm of BLOB_WIDTH.
const LOG_BLOB_WIDTH: usize = 12;

pub static BLS_MODULUS: LazyLock<U256> = LazyLock::new(|| {
    use openvm_pairing_guest::algebra::IntMod;
    U256::from_le_bytes(Scalar::MODULUS)
});

pub static PRIMITIVE_ROOTS_OF_UNITY: LazyLock<Scalar> = LazyLock::new(|| {
    use openvm_pairing_guest::algebra::IntMod;
    Scalar::from_u8(7)
});

pub static ROOTS_OF_UNITY: LazyLock<Vec<Scalar>> = LazyLock::new(|| {

    // https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#constants
    let primitive_root_of_unity = PRIMITIVE_ROOTS_OF_UNITY.clone();
    let modulus = *BLS_MODULUS;

    let exponent = (modulus - U256::from(1)) / U256::from(4096);
    //let root_of_unity = primitive_root_of_unity.pow(exponent.as_limbs());
    let root_of_unity = ExpBytes::exp_bytes(&primitive_root_of_unity, true, &exponent.to_be_bytes::<32>());

    let ascending_order: Vec<_> = std::iter::successors(Some(Scalar::ONE), |x| Some(x.clone() * root_of_unity.clone()))
        .take(BLOB_WIDTH)
        .collect();
    (0..BLOB_WIDTH)
        .map(|i| {
            let j = u16::try_from(i).unwrap().reverse_bits() >> (16 - LOG_BLOB_WIDTH);
            ascending_order[usize::from(j)].clone()
        })
        .collect()
});

fn interpolate(z: Scalar, coefficients: &[Scalar; BLOB_WIDTH]) -> Scalar {
    let blob_width = u64::try_from(BLOB_WIDTH).unwrap();
    (ExpBytes::exp_bytes(&z, true, &blob_width.to_be_bytes()) - Scalar::ONE)
        * ROOTS_OF_UNITY
            .iter()
            .zip_eq(coefficients)
            .map(|(root, f)| f * root * (z.clone() - root).invert())
            .sum::<Scalar>()
        * Scalar::from_u64(blob_width).invert()
}

pub fn point_evaluation(coefficients : &[U256; BLOB_WIDTH], challenge_digest: U256) -> (U256, U256) {
    use openvm_pairing_guest::algebra::IntMod;
    // blob polynomial in evaluation form.
    //
    // also termed P(x)
    let coefficients_as_scalars = coefficients.map(|coeff| Scalar::from_le_bytes(coeff.as_le_slice()));

    let challenge = challenge_digest % *BLS_MODULUS;

    // y = P(z)
    let y = U256::from_le_slice(
        interpolate(Scalar::from_le_bytes(challenge.as_le_slice()), &coefficients_as_scalars).as_le_bytes(),
    );
    (challenge, y)

}

#[cfg(feature="gen_curve")]
#[test]
fn test_constant_in_openvm() {

    use super::general::ROOTS_OF_UNITY as ROOTS_OF_UNITY_GEN;

    assert_eq!(ROOTS_OF_UNITY_GEN.len(), ROOTS_OF_UNITY.len());

    for (unity_gen, unity) in ROOTS_OF_UNITY_GEN.iter().zip(&*ROOTS_OF_UNITY){
        assert_eq!(Vec::from(unity.as_le_bytes()), Vec::from(unity_gen.to_bytes()));
    }
}