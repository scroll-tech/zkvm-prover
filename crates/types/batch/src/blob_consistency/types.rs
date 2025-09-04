

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

impl ToIntrinsic for Bls12_381_G1 {
    type IntrinsicType = G1Affine;

    fn to_intrinsic(&self) -> Self::IntrinsicType {
        G1Affine::from_xy_unchecked(self.x.to_intrinsic(), self.y.to_intrinsic())
    }
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