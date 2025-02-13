use std::sync::LazyLock;

use algebra::{Field, IntMod};
use alloy_primitives::U256;
use itertools::Itertools;
use openvm_pairing_guest::{
    algebra, bls12_381::{Bls12_381, Fp, Fp2, Scalar},
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
