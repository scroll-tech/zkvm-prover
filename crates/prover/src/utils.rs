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
