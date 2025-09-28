use alloy_consensus::crypto::RecoveryError;
use alloy_primitives::Address;
use sbv_primitives::types::revm::precompile;
use sbv_primitives::types::revm::precompile::PrecompileError;
use std::sync::Arc;

mod bn254;
mod secp256k1;

/// crypto operations provider
#[derive(Debug)]
pub struct Crypto;

impl Crypto {
    /// Install this as the global crypto provider.
    ///
    /// # Panics
    ///
    /// Panics if a crypto provider has already been installed.
    pub fn install() {
        assert!(precompile::install_crypto(Self));
        alloy_consensus::crypto::install_default_provider(Arc::new(Self))
            .expect("crypto provider already set");
    }
}

impl precompile::Crypto for Crypto {
    #[inline]
    fn sha256(&self, input: &[u8]) -> [u8; 32] {
        openvm_sha2::sha256(input)
    }

    #[inline]
    fn bn254_g1_add(&self, p1: &[u8], p2: &[u8]) -> Result<[u8; 64], PrecompileError> {
        let p1 = bn254::read_g1_point(p1)?;
        let p2 = bn254::read_g1_point(p2)?;
        let result = bn254::g1_point_add(p1, p2);
        Ok(bn254::encode_g1_point(result))
    }

    #[inline]
    fn bn254_g1_mul(&self, point: &[u8], scalar: &[u8]) -> Result<[u8; 64], PrecompileError> {
        let p = bn254::read_g1_point(point)?;
        let fr = bn254::read_scalar(scalar);
        let result = bn254::g1_point_mul(p, fr);
        Ok(bn254::encode_g1_point(result))
    }

    #[inline]
    fn bn254_pairing_check(&self, pairs: &[(&[u8], &[u8])]) -> Result<bool, PrecompileError> {
        bn254::pairing_check(pairs)
    }

    #[inline]
    fn secp256k1_ecrecover(
        &self,
        sig: &[u8; 64],
        recid: u8,
        msg: &[u8; 32],
    ) -> Result<[u8; 32], PrecompileError> {
        secp256k1::ecrecover(sig, recid, msg)
            .ok()
            .ok_or_else(|| PrecompileError::other("ecrecover failed"))
    }
}

impl alloy_consensus::crypto::backend::CryptoProvider for Crypto {
    #[inline]
    fn recover_signer_unchecked(
        &self,
        sig: &[u8; 65],
        msg: &[u8; 32],
    ) -> Result<Address, RecoveryError> {
        secp256k1::ecrecover((&sig[..64]).try_into().unwrap(), sig[64], msg)
            .map(|res| Address::from_slice(&res[12..]))
            .map_err(RecoveryError::from_source)
    }
}
