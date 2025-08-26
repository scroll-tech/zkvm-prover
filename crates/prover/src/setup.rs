use std::{fs::read_to_string, path::Path};

use openvm_circuit::arch::instructions::{
    exe::{FnBounds, MemoryImage, VmExe},
    instruction::{DebugInfo, Instruction},
    program::Program,
};
use openvm_sdk::{
    F,
    config::{AppConfig, SdkVmConfig},
    fs::{read_exe_from_file, read_from_file_bitcode},
};

use crate::Error;

/// Wrapper around [`openvm_sdk::fs::read_exe_from_file`].
pub fn read_app_exe<P: AsRef<Path>>(path: P) -> Result<VmExe<F>, Error> {
    if let Ok(exe) = read_exe_from_file(&path) {
        return Ok(exe);
    }
    println!("loading vmexe failed, trying old format..");
    #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
    pub struct OldProgram<F> {
        pub instructions_and_debug_infos: Vec<Option<(Instruction<F>, Option<DebugInfo>)>>,
        pub step: u32,
        pub pc_base: u32,
        pub max_num_public_values: usize,
    }
    #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(bound(
        serialize = "F: serde::Serialize",
        deserialize = "F: std::cmp::Ord + serde::Deserialize<'de>"
    ))]
    pub struct OldVmExe<F> {
        pub program: OldProgram<F>,
        pub pc_start: u32,
        pub init_memory: MemoryImage<F>,
        pub fn_bounds: FnBounds,
    }
    let old_exe: OldVmExe<F> = read_from_file_bitcode(&path).map_err(|e| Error::Setup {
        path: path.as_ref().into(),
        src: e.to_string(),
    })?;
    let exe = VmExe::<F> {
        pc_start: old_exe.pc_start,
        init_memory: old_exe.init_memory,
        fn_bounds: old_exe.fn_bounds,
        program: Program::<F> {
            instructions_and_debug_infos: old_exe.program.instructions_and_debug_infos,
            step: old_exe.program.step,
            pc_base: old_exe.program.pc_base,
        },
    };
    Ok(exe)
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
