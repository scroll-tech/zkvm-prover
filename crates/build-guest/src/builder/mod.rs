use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use openvm_build::GuestOptions;
use openvm_instructions::exe::VmExe;
use openvm_sdk::{
    F, Sdk,
    config::{AppConfig, SdkVmConfig},
    fs::write_exe_to_file,
};

use openvm_transpiler::elf::Elf;
use tracing::instrument;

/// Feature to enable while building the guest program.
const FEATURE_SCROLL: &str = "scroll";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// Build the ELF binary from the circuit program.
#[instrument("ProverTester::build", fields(project_root))]
pub fn build(project_root: &str) -> eyre::Result<Elf> {
    let guest_opts = GuestOptions::default().with_features([FEATURE_SCROLL]);
    #[cfg(feature = "euclidv2")]
    let guest_opts = guest_opts.with_features(["euclidv2"]);
    let elf = Sdk.build(guest_opts, project_root, &Default::default())?;
    Ok(elf)
}

/// Transpile the ELF into a VmExe.
#[instrument(
    "ProverTester::transpile",
    skip_all,
    fields(path_app_config, path_app_exe)
)]
pub fn transpile(
    project_root: &str,
    elf: Elf,
) -> eyre::Result<(PathBuf, AppConfig<SdkVmConfig>, PathBuf, VmExe<F>)> {
    let is_chunk = project_root.contains("chunk");
    // Create the assets dir if not already present.
    let path_assets = Path::new(project_root).join("openvm");
    std::fs::create_dir_all(&path_assets)?;

    // First read the app config specified in the project's root directory.
    let path_app_config = Path::new(project_root).join(FD_APP_CONFIG);
    let mut app_config: AppConfig<SdkVmConfig> =
        toml::from_str(&read_to_string(&path_app_config).unwrap()).unwrap();

    println!(
        "{project_root} app config: {}",
        toml::to_string_pretty(&app_config).unwrap()
    );

    // FIXME: additional app config for batch and bundle guest program.
    if !is_chunk {
        app_config.app_vm_config.castf = Some(openvm_native_circuit::CastFExtension);
    }

    // Transpile ELF to openvm executable.
    let mut transpiler = app_config.app_vm_config.transpiler();
    if !is_chunk {
        transpiler =
            transpiler.with_extension(openvm_native_transpiler::LongFormTranspilerExtension);
    }
    let app_exe = Sdk.transpile(elf, transpiler)?;

    // Write exe to disc.
    let path_app_exe = path_assets.join(FD_APP_EXE);
    write_exe_to_file(app_exe.clone(), &path_app_exe)?;

    Ok((path_app_config, app_config, path_app_exe, app_exe))
}
