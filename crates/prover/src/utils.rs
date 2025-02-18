use std::path::Path;

use git_version::git_version;
use serde::{
    Serialize,
    de::{Deserialize, DeserializeOwned},
};

use crate::Error;

pub const GIT_VERSION: &str = git_version!(args = ["--abbrev=7", "--always"]);

/// Shortened git commit ref from [`scroll_zkvm_prover`].
pub fn short_git_version() -> String {
    let commit_version = GIT_VERSION.split('-').last().unwrap();

    // Check if use commit object as fallback.
    if commit_version.len() < 8 {
        commit_version.to_string()
    } else {
        commit_version[1..8].to_string()
    }
}

/// Wrapper to read JSON file.
pub fn read_json<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T, Error> {
    let path = path.as_ref();
    let bytes = read(path)?;
    serde_json::from_slice(&bytes).map_err(|source| Error::JsonReadWrite {
        source,
        path: path.to_path_buf(),
    })
}

/// Wrapper to read JSON that might be deeply nested.
pub fn read_json_deep<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T, Error> {
    let fd = std::fs::File::open(path)?;
    let mut deserializer = serde_json::Deserializer::from_reader(fd);
    deserializer.disable_recursion_limit();
    let deserializer = serde_stacker::Deserializer::new(&mut deserializer);
    Ok(Deserialize::deserialize(deserializer)?)
}

/// Read bytes from a file.
pub fn read<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, Error> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|source| Error::IoReadWrite {
        source,
        path: path.into(),
    })
}

/// Serialize the provided type to JSON format and write to the given path.
pub fn write_json<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<(), Error> {
    let mut writer = std::fs::File::create(path)?;
    Ok(serde_json::to_writer(&mut writer, value)?)
}

/// Wrapper functionality to write bytes to a file.
pub fn write<P: AsRef<Path>>(path: P, data: &[u8]) -> Result<(), Error> {
    let path = path.as_ref();
    Ok(std::fs::write(path, data)?)
}

pub mod base64 {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub mod point_eval {
    use c_kzg;
    use sbv::primitives::{B256 as H256, U256};

    const N_BLOB_FIELDS: usize = 4096;
    const N_BLOB_BYTES: usize = 32 * N_BLOB_FIELDS;
    const N_ENVELOPED_BYTES: usize = 31 * N_BLOB_FIELDS;

    type BlobByte = c_kzg::Blob;

    /// translate the enveloped bytes to fixed length blob byte
    /// (use 32 bytes in blob to envelop each 31 byte)
    pub fn to_blob_bytes(enveloped_bytes: &[u8]) -> BlobByte {
        let mut blob_bytes = [0u8; N_BLOB_BYTES];

        assert!(
            blob_bytes.len() <= N_ENVELOPED_BYTES,
            "too many bytes in batch data"
        );

        for (i, &byte) in enveloped_bytes.iter().enumerate() {
            blob_bytes[(i / 31) * 32 + (i % 31)] = byte;
        }

        BlobByte::new(blob_bytes)
    }

    /// turn envolped bytes into kzg commitment
    pub fn blob_to_kzg_commitment(blob_bytes: &BlobByte) -> c_kzg::KzgCommitment {
        c_kzg::KzgCommitment::blob_to_kzg_commitment(blob_bytes, c_kzg::ethereum_kzg_settings())
            .expect("blob to kzg commitment should succeed")
    }

    /// feasible entry to get versioned hash
    pub fn get_versioned_hash(commitment: &c_kzg::KzgCommitment) -> H256 {
        H256::new(
            revm::precompile::kzg_point_evaluation::kzg_to_versioned_hash(commitment.as_slice()),
        )
    }

    /// calculate the proof and y from challenge
    pub fn get_kzg_proof(blob_bytes: &BlobByte, challenge: H256) -> (c_kzg::KzgProof, U256) {
        // notice U256 use little endian while c_kzg use be
        let bls12_381_modulus = U256::from_limbs([
            0xffff_ffff_0000_0001,
            0x53bd_a402_fffe_5bfe,
            0x3339_d808_09a1_d805,
            0x73ed_a753_299d_7d48,
        ]);

        let scalar_chg = U256::from_be_bytes(challenge.0) % bls12_381_modulus;

        let (proof, y) = c_kzg::KzgProof::compute_kzg_proof(
            &blob_bytes,
            &c_kzg::Bytes32::new(scalar_chg.to_be_bytes()),
            c_kzg::ethereum_kzg_settings(),
        )
        .expect("kzg proof should succeed");

        (proof, U256::from_be_bytes(*y.as_ref()))
    }
}
