use hex_literal::hex;
use openvm_build::{GuestOptions, TargetFilter};
use std::{
    fs::read_to_string,
    path::{Path, PathBuf},
};

use openvm_build::{build_guest_package, find_unique_executable, get_package};
use openvm_ecc_guest::CyclicGroup;
use openvm_instructions::exe::VmExe;
use openvm_sdk::{
    F, Sdk,
    config::{AppConfig, SdkVmConfig, UnitStruct},
    fs::write_exe_to_file,
};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE};

// use openvm_transpiler::elf::Elf;
use tracing::instrument;

/// Feature to enable while building the guest program.
const FEATURE_SCROLL: &str = "scroll";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

pub fn build_elf<P: AsRef<Path>>(
    guest_opts: GuestOptions,
    pkg_dir: P,
    target_filter: &Option<TargetFilter>,
) -> eyre::Result<PathBuf> {
    let pkg = get_package(pkg_dir.as_ref());
    let target_dir = match build_guest_package(&pkg, &guest_opts, None, target_filter) {
        Ok(target_dir) => target_dir,
        Err(Some(code)) => {
            return Err(eyre::eyre!("Failed to build guest: code = {}", code));
        }
        Err(None) => {
            return Err(eyre::eyre!(
                "Failed to build guest (OPENVM_SKIP_BUILD is set)"
            ));
        }
    };

    find_unique_executable(pkg_dir, target_dir, target_filter)
}

/// wtf
fn binary_patch(elf_bin: &[u8]) -> Vec<u8> {
    use openvm_algebra_guest::IntMod;
    use openvm_ecc_guest::weierstrass::WeierstrassPoint;
    let replaces = [
        openvm_ecc_guest::p256::P256Point::GENERATOR
            .x()
            .as_le_bytes(),
        openvm_ecc_guest::p256::P256Point::GENERATOR
            .y()
            .as_le_bytes(),
        openvm_ecc_guest::p256::P256Point::NEG_GENERATOR
            .y()
            .as_le_bytes(),
    ];
    if replaces[0][0] != 107u8 {
        println!("patching not needed");
        return elf_bin.to_vec();
    }

    let mut new_elf_bin = elf_bin.to_vec();
    for old_hex in replaces {
        let mut new_hex = old_hex.to_vec();
        new_hex.reverse();
        for i in 0..new_elf_bin.len().saturating_sub(31) {
            let end = i + 32;
            if &new_elf_bin[i..end] == old_hex {
                println!("replace at {i}");
                new_elf_bin[i..end].copy_from_slice(&new_hex);
            }
        }
    }
    new_elf_bin
}

/// Build the ELF binary from the circuit program.
#[instrument("ProverTester::build", fields(project_root))]
pub fn build(project_root: &str) -> eyre::Result<Elf> {
    let guest_opts = GuestOptions::default().with_features([FEATURE_SCROLL]);
    #[cfg(feature = "euclidv2")]
    let guest_opts = guest_opts.with_features(["euclidv2"]);
    let elf_path = build_elf(guest_opts, project_root, &Default::default())?;
    let data = std::fs::read(&elf_path)?;
    let new_data = binary_patch(&data);
    Elf::decode(&new_data, MEM_SIZE as u32)
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
    // Create the assets dir if not already present.
    let path_assets = Path::new(project_root).join("openvm");
    std::fs::create_dir_all(&path_assets)?;

    // First read the app config specified in the project's root directory.
    let path_app_config = Path::new(project_root).join(FD_APP_CONFIG);
    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(&read_to_string(&path_app_config).unwrap()).unwrap();

    println!(
        "{project_root} app config: {}",
        toml::to_string_pretty(&app_config).unwrap()
    );

    // Transpile ELF to openvm executable.
    let transpiler = app_config
        .app_vm_config
        .transpiler()
        .with_extension(openvm_native_transpiler::LongFormTranspilerExtension);
    let app_exe = Sdk.transpile(elf, transpiler)?;

    // Write exe to disc.
    let path_app_exe = path_assets.join(FD_APP_EXE);
    write_exe_to_file(app_exe.clone(), &path_app_exe)?;

    Ok((path_app_config, app_config, path_app_exe, app_exe))
}
