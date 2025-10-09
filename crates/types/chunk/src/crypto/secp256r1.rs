//! Copied from <https://github.com/bluealloy/revm/blob/9cdc7f15b88bdf0359a48dca8cb5ea6193f16fa3/crates/precompile/src/secp256r1.rs#L102-L111>
use openvm_p256::EncodedPoint;
use openvm_p256::ecdsa::signature::hazmat::PrehashVerifier;
use openvm_p256::ecdsa::{Signature, VerifyingKey};

pub fn secp256r1_verify_signature(msg: &[u8; 32], sig: &[u8; 64], pk: &[u8; 64]) -> Option<()> {
    // Can fail only if the input is not exact length.
    let signature = Signature::from_slice(sig).ok()?;
    // Decode the public key bytes (x,y coordinates) using EncodedPoint
    let encoded_point = EncodedPoint::from_untagged_bytes(pk.into());
    // Create VerifyingKey from the encoded point
    let public_key = VerifyingKey::from_encoded_point(&encoded_point).ok()?;

    public_key.verify_prehash(msg, &signature).ok()
}
