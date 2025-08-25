use std::path::Path;

use git_version::git_version;
use serde::{
    Serialize,
    de::{Deserialize, DeserializeOwned},
};

use crate::Error;

pub mod vm;

pub const GIT_VERSION: &str = git_version!(args = ["--abbrev=7", "--always"]);

/// Shortened git commit ref from [`scroll_zkvm_prover`].
pub fn short_git_version() -> String {
    let commit_version = GIT_VERSION.split('-').next_back().unwrap();

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

/// Serialize the provided type with bincode and write to the given path.
pub fn write_bin<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<(), Error> {
    let data = bincode_v1::serialize(value).map_err(|e| Error::Custom(e.to_string()))?;
    write(path, &data)
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

pub mod as_base64 {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};

    pub fn serialize<S: Serializer, T: Serialize>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        let v_bytes = bincode_v1::serialize(v).map_err(serde::ser::Error::custom)?;
        let v_base64 = BASE64_STANDARD.encode(&v_bytes);
        String::serialize(&v_base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: DeserializeOwned>(
        d: D,
    ) -> Result<T, D::Error> {
        let v_base64 = String::deserialize(d)?;
        let v_bytes = BASE64_STANDARD
            .decode(v_base64.as_bytes())
            .map_err(serde::de::Error::custom)?;
        bincode_v1::deserialize(&v_bytes).map_err(serde::de::Error::custom)
    }
}
