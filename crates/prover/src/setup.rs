use std::{collections::BTreeMap, fs::read_to_string, path::Path};

use openvm_circuit::arch::instructions::{
    exe::{FnBounds, VmExe},
    instruction::{DebugInfo, Instruction},
    program::Program,
};
use openvm_native_recursion::halo2::utils::CacheHalo2ParamsReader;
use openvm_sdk::fs::read_object_from_file;
use openvm_sdk::{
    DefaultStaticVerifierPvHandler, F, Sdk,
    commit::AppExecutionCommit,
    config::{AppConfig, SdkVmConfig},
    keygen::{AggProvingKey, AppProvingKey},
};
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{ExtensionField, PackedValue},
    p3_baby_bear::BabyBear,
};

use crate::Error;

/// Wrapper around [`openvm_sdk::fs::read_exe_from_file`].
pub fn read_app_exe<P: AsRef<Path>>(path: P) -> Result<VmExe<F>, Error> {
    let r = read_object_from_file(&path);
    if let Ok(r) = r {
        return Ok(r);
    }

    /// Executable program for OpenVM.
    #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(bound(serialize = "F: Serialize", deserialize = "F: Deserialize<'de>"))]
    pub struct OldProgram<F> {
        #[serde(
            serialize_with = "serialize_instructions_and_debug_infos",
            deserialize_with = "deserialize_instructions_and_debug_infos"
        )]
        pub instructions_and_debug_infos: Vec<Option<(Instruction<F>, Option<DebugInfo>)>>,
        pub step: u32,
        pub pc_base: u32,
        //pub max_num_public_values: usize,
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
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    // `debug_info` is based on the symbol table of the binary. Usually serializing `debug_info` is not
    // meaningful because the program is executed by another binary. So here we only serialize
    // instructions.
    fn serialize_instructions_and_debug_infos<F: Serialize, S: Serializer>(
        data: &[Option<(Instruction<F>, Option<DebugInfo>)>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut ins_data = Vec::with_capacity(data.len());
        let total_len = data.len() as u32;
        for (i, o) in data.iter().enumerate() {
            if let Some(o) = o {
                ins_data.push((&o.0, i as u32));
            }
        }
        (ins_data, total_len).serialize(serializer)
    }

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

    let old_exe: OldVmExe<F> = read_object_from_file(&path).unwrap();
    use openvm_stark_sdk::openvm_stark_backend::p3_field::FieldAlgebra;
    use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
    let exe = VmExe::<F> {
        program: Program::<F> {
            instructions_and_debug_infos: old_exe.program.instructions_and_debug_infos,
            //step: old_exe.program.step,
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
