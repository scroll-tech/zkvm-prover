use std::{collections::BTreeMap, fs::read_to_string, path::Path};

use openvm_circuit::arch::instructions::{
    exe::{FnBounds, VmExe},
    instruction::{DebugInfo, Instruction},
    program::Program,
};
use openvm_native_recursion::halo2::utils::CacheHalo2ParamsReader;
use openvm_sdk::{
    DefaultStaticVerifierPvHandler, F, Sdk,
    commit::AppExecutionCommit,
    config::{AggConfig, AppConfig, SdkVmConfig},
    fs::{read_app_pk_from_file, read_exe_from_file, read_from_file_bitcode},
    keygen::{AggProvingKey, AppProvingKey},
};
use openvm_stark_sdk::{
    openvm_stark_backend::p3_field::{ExtensionField, PackedValue},
    p3_baby_bear::BabyBear,
};

use crate::Error;

/// Wrapper around [`openvm_sdk::fs::read_exe_from_file`].
pub fn read_app_exe<P: AsRef<Path>>(path: P) -> Result<VmExe<F>, Error> {
    return Ok(read_exe_from_file(path).unwrap());
    /// Executable program for OpenVM.
    #[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(bound(
        serialize = "F: serde::Serialize",
        deserialize = "F: std::cmp::Ord + serde::Deserialize<'de>"
    ))]
    pub struct OldVmExe<F> {
        /// Program to execute.
        pub program: Program<F>,
        /// Start address of pc.
        pub pc_start: u32,
        /// Initial memory image.
        pub init_memory: BTreeMap<(u32, u32), F>,
        /// Starting + ending bounds for each function.
        pub fn_bounds: FnBounds,
    }

    let exe: OldVmExe<F> = read_from_file_bitcode(&path).unwrap();
    use openvm_stark_sdk::openvm_stark_backend::p3_field::FieldAlgebra;
    use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
    let exe = VmExe::<F> {
        program: exe.program,
        pc_start: exe.pc_start,
        init_memory: exe
            .init_memory
            .into_iter()
            .map(|(k, v)| {
                assert!(v < F::from_canonical_u32(256u32));
                (k, v.as_canonical_u32() as u8)
            })
            .collect(),
        fn_bounds: exe.fn_bounds,
    };
    Ok(exe)
}

/// Wrapper around [`openvm_sdk::fs::read_app_pk_from_file`].
pub fn read_app_pk<P: AsRef<Path>>(path: P) -> Result<AppProvingKey<SdkVmConfig>, Error> {
    read_app_pk_from_file(&path).map_err(|e| Error::Setup {
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

/// Compute commitments to the app.
pub fn compute_commitments(
    app_exe: VmExe<F>,
    app_pk: AppProvingKey<SdkVmConfig>,
) -> Result<AppExecutionCommit, Error> {
    let committed_exe = Sdk::new()
        .commit_app_exe(app_pk.app_fri_params(), app_exe)
        .map_err(|e| Error::Commit(e.to_string()))?;
    Ok(AppExecutionCommit::compute(
        &app_pk.app_vm_pk.vm_config,
        &committed_exe,
        &app_pk.leaf_committed_exe,
    ))
}

/// Generate STARK aggregation [proving key][`openvm_sdk::keygen::AggProvingKey`].
pub fn gen_agg_pk(params_dir: &str) -> Result<AggProvingKey, Error> {
    let halo2_params_reader = CacheHalo2ParamsReader::new(params_dir);
    Sdk::new()
        .agg_keygen(
            AggConfig::default(),
            &halo2_params_reader,
            &DefaultStaticVerifierPvHandler,
        )
        .map_err(|e| Error::Keygen(e.to_string()))
}
