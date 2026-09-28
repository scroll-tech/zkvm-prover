use std::{fs::read_to_string, path::Path};

use openvm_circuit::arch::instructions::exe::VmExe;
use openvm_sdk::config::AppConfig;
use openvm_sdk::fs::read_object_from_file;
use openvm_sdk_config::SdkVmConfig;

use crate::Error;

/// Read and deserialize [`VmExe`] from the given path.
pub fn read_app_exe<P: AsRef<Path>>(path: P) -> Result<VmExe, Error> {
    read_object_from_file(&path).map_err(|e| Error::Setup {
        path: path.as_ref().into(),
        src: e.to_string(),
    })
}

/// Read and deserialize [`openvm_sdk::config::AppConfig`] from the given path to the TOML config.
pub fn read_app_config<P: AsRef<Path>>(path: P) -> Result<AppConfig<SdkVmConfig>, Error> {
    let toml_str = read_to_string(&path).map_err(|e| Error::Setup {
        path: path.as_ref().into(),
        src: e.to_string(),
    })?;

    toml::from_str(&toml_str).map_err(|e| Error::Setup {
        path: path.as_ref().into(),
        src: e.to_string(),
    })
}
