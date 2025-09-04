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

pub fn save_stdin_as_json(stdin: &openvm_sdk::StdIn, filename: &str) {
    // dump stdin to file
    let mut json: serde_json::Value = serde_json::from_str("{\"input\":[]}").unwrap();
    let json_input = json["input"].as_array_mut().unwrap();
    for item in &stdin.buffer {
        use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
        let mut bytes: Vec<u8> = vec![0x02];
        for f in item {
            let u32_bytes = f.as_canonical_u32().to_le_bytes();
            bytes.extend_from_slice(&u32_bytes);
        }
        json_input.push(serde_json::Value::String(format!(
            "0x{}",
            hex::encode(bytes)
        )));
    }
    if let Err(e) = std::fs::write(&filename, serde_json::to_string_pretty(&json).unwrap()) {
        tracing::warn!("Failed to write stdin to {}: {}", filename, e);
    } else {
        tracing::info!("Wrote stdin to {}", filename);
    }
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

/// Print GPU memory usage information including used, free, and total memory in GiB.
pub fn print_gpu_memory_usage() -> Result<(), Error> {
    #[cfg(feature = "cuda")]
    {
        match try_print_gpu_memory_cudarc() {
            Ok(_) => return Ok(()),
            Err(e) => {
                println!("GPU memory monitoring failed: {}", e);
                println!("Make sure CUDA is properly installed and cudarc dependency is added");
            }
        }
    }

    #[cfg(not(feature = "cuda"))]
    {
        println!("GPU memory monitoring not available (CUDA feature not enabled)");
    }

    Ok(())
}

#[cfg(feature = "cuda")]
fn try_print_gpu_memory_cudarc() -> Result<(), Box<dyn std::error::Error>> {
    use cudarc::driver::result::{device, mem_get_info};

    // Get device count without creating new contexts
    let device_count = device::get_count()? as usize;

    if device_count == 0 {
        println!("No CUDA devices found");
        return Ok(());
    }

    println!("GPU Memory Usage:");
    println!("{:-<50}", "");

    // Try to get memory info from current context instead of creating new ones
    match mem_get_info() {
        Ok((free_bytes, total_bytes)) => {
            let total_gib = total_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let free_gib = free_bytes as f64 / (1024.0 * 1024.0 * 1024.0);
            let used_gib = total_gib - free_gib;
            let usage_percent = (used_gib / total_gib) * 100.0;

            println!(
                "Current GPU: Used: {:.2} GiB, Free: {:.2} GiB, Total: {:.2} GiB ({:.1}% used)",
                used_gib, free_gib, total_gib, usage_percent
            );
        }
        Err(e) => {
            println!("Could not get GPU memory info (no active context): {}", e);
        }
    }

    println!("{:-<50}", "");

    Ok(())
}
