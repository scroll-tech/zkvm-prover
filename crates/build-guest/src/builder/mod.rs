use openvm_build::GuestOptions;
use std::{fs::read_to_string, path::Path};

use openvm_instructions::exe::VmExe;
use openvm_sdk::{
    F, Sdk,
    config::{AppConfig, SdkVmConfig},
    fs::write_exe_to_file,
};
use openvm_transpiler::elf::Elf;

use tracing::instrument;

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// Build the ELF binary from the circuit program.
#[instrument("BuildGuest::build", fields(project_root), skip(feature_flags))]
pub fn build<S: AsRef<str>>(
    project_root: &str,
    feature_flags: impl IntoIterator<Item = S>,
) -> eyre::Result<Elf> {
    let guest_opts = GuestOptions::default();
    let guest_opts = guest_opts.with_features(feature_flags);
    let guest_opts = guest_opts.with_profile("maxperf".to_string());
    Sdk::new().build(guest_opts, project_root, &Default::default())
}

pub fn load_app_config(project_root: &str) -> eyre::Result<AppConfig<SdkVmConfig>> {
    // First read the app config specified in the project's root directory.
    let path_app_config = Path::new(project_root).join(FD_APP_CONFIG);
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(&read_to_string(&path_app_config).unwrap()).unwrap();
    println!(
        "{project_root} app config: {}",
        toml::to_string_pretty(&app_config).unwrap()
    );
    Ok(app_config)
}

/// Transpile the ELF into a VmExe.
#[instrument("BuildGuest::transpile", skip_all, fields(project_root))]
pub fn transpile(
    project_root: &str,
    elf: Elf,
    fd_app_exe: Option<&str>,
    app_config: AppConfig<SdkVmConfig>,
) -> eyre::Result<VmExe<F>> {
    // Create the assets dir if not already present.
    let path_assets = Path::new(project_root).join("openvm");
    std::fs::create_dir_all(&path_assets)?;

    // Transpile ELF to openvm executable.
    let transpiler = app_config
        .app_vm_config
        .transpiler()
        .with_extension(openvm_native_transpiler::LongFormTranspilerExtension);
    let app_exe = Sdk::new().transpile(elf, transpiler)?;

    // Write exe to disc.
    let path_app_exe = path_assets.join(fd_app_exe.unwrap_or(FD_APP_EXE));
    write_exe_to_file(app_exe.clone(), &path_app_exe)?;

    println!("exe written to {path_app_exe:?}");

    Ok(app_exe)
}
