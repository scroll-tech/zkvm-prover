use std::{collections::BTreeMap, fs::read_to_string, path::Path};

use openvm_circuit::arch::instructions::{
    exe::{FnBounds, VmExe},
    instruction::{DebugInfo, Instruction},
    program::Program,
};
use openvm_sdk::fs::read_object_from_file;
use openvm_sdk::{
    F,
    config::{AppConfig, SdkVmConfig},
};

use crate::Error;

/// Wrapper around [`openvm_sdk::fs::read_exe_from_file`].
pub fn read_app_exe<P: AsRef<Path>>(path: P) -> Result<VmExe<F>, Error> {
    if let Ok(r) = read_object_from_file(&path) {
        return Ok(r);
    }

    println!("loading vmexe failed, trying old format..");

    /// Executable program for OpenVM.
    #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de>"))]
    pub struct OldProgram<F> {
        #[serde(deserialize_with = "deserialize_instructions_and_debug_infos")]
        pub instructions_and_debug_infos: Vec<Option<(Instruction<F>, Option<DebugInfo>)>>,
        pub step: u32,
        pub pc_base: u32,
    }
    #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(bound(
        serialize = "F: serde::Serialize",
        deserialize = "F: std::cmp::Ord + serde::Deserialize<'de>"
    ))]
    pub struct OldVmExe<F> {
        /// Program to execute.
        pub program: OldProgram<F>,
        /// Start address of pc.
        pub pc_start: u32,
        /// Initial memory image.
        pub init_memory: BTreeMap<(u32, u32), F>,
        /// Starting + ending bounds for each function.
        pub fn_bounds: FnBounds,
    }
    use serde::{Deserialize, Deserializer, Serialize};

    #[allow(clippy::type_complexity)]
    fn deserialize_instructions_and_debug_infos<'de, F: Deserialize<'de>, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Option<(Instruction<F>, Option<DebugInfo>)>>, D::Error> {
        let (inst_data, total_len): (Vec<(Instruction<F>, u32)>, u32) =
            Deserialize::deserialize(deserializer)?;
        let mut ret: Vec<Option<(Instruction<F>, Option<DebugInfo>)>> = Vec::new();
        ret.resize_with(total_len as usize, || None);
        for (inst, i) in inst_data {
            ret[i as usize] = Some((inst, None));
        }
        Ok(ret)
    }

    let old_exe: OldVmExe<F> = read_object_from_file(&path).map_err(|e| Error::Setup {
        path: path.as_ref().into(),
        src: e.to_string(),
    })?;
    use openvm_stark_sdk::openvm_stark_backend::p3_field::FieldAlgebra;
    use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
    let exe = VmExe::<F> {
        program: Program::<F> {
            instructions_and_debug_infos: old_exe.program.instructions_and_debug_infos,
            pc_base: old_exe.program.pc_base,
        },
        pc_start: old_exe.pc_start,
        init_memory: old_exe
            .init_memory
            .into_iter()
            .map(|(k, v)| {
                assert!(v < F::from_canonical_u32(256u32));
                (k, v.as_canonical_u32() as u8)
            })
            .collect(),
        fn_bounds: old_exe.fn_bounds,
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
