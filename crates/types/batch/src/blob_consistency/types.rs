
use halo2curves_axiom::bls12_381::{
    Fq as Bls12_381_Fq, G1Affine as Bls12_381_G1, G2Affine as Bls12_381_G2,
};
use openvm_ecc_guest::weierstrass::WeierstrassPoint;
use openvm_algebra_guest::IntMod;
use openvm_pairing::bls12_381::{Fp, Fp2, G1Affine, G2Affine};

/// Helper trait that provides functionality to convert the given type from native to the desired intrinsic type 
pub trait ToIntrinsic {
    /// The desired intrinsic type
    type IntrinsicType;

    /// Convert the given type from native to the desired intrinsic type 
    fn to_intrinsic(&self) -> Self::IntrinsicType;
}

impl ToIntrinsic for Bls12_381_Fq {
    type IntrinsicType = Fp;

    fn to_intrinsic(&self) -> Self::IntrinsicType {
        let bytes = self.to_bytes();
        Fp::from_le_bytes_unchecked(&bytes)
    }
}

pub fn from_intrinsic_fp(x: Fp) -> Bls12_381_Fq {
    Bls12_381_Fq::from_bytes(x.as_le_bytes().try_into().unwrap()).unwrap()
}

impl ToIntrinsic for Bls12_381_G1 {
    type IntrinsicType = G1Affine;

    fn to_intrinsic(&self) -> Self::IntrinsicType {
        G1Affine::from_xy_unchecked(self.x.to_intrinsic(), self.y.to_intrinsic())
    }
}

pub fn from_intrinsic_g1(p: G1Affine) -> Bls12_381_G1 {
    let mut r = Bls12_381_G1::generator();
    r.x = from_intrinsic_fp(p.x().clone());
    r.y = from_intrinsic_fp(p.y().clone());
    r
}

impl ToIntrinsic for Bls12_381_G2 {
    type IntrinsicType = G2Affine;

    fn to_intrinsic(&self) -> Self::IntrinsicType {
        G2Affine::from_xy_unchecked(
            Fp2::new(self.x.c0.to_intrinsic(), self.x.c1.to_intrinsic()),
            Fp2::new(self.y.c0.to_intrinsic(), self.y.c1.to_intrinsic()),
        )
    }
}
