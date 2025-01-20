use std::path::{Path, PathBuf};

use openvm_build::GuestOptions;
use openvm_sdk::{
    Sdk,
    config::{AppConfig, SdkVmConfig},
    fs::{write_app_pk_to_file, write_exe_to_file},
};
use openvm_transpiler::elf::Elf;
use scroll_zkvm_prover::{ProverVerifier, setup::read_app_config};

/// Feature to enable while building the guest program.
const FEATURE_SCROLL: &str = "scroll";

/// Path to store release assets, root directory of zkvm-prover repository.
const DIR_OPENVM_ASSETS: &str = "./../../.openvm";

/// Extension for app openvm config.
const EXT_APP_CONFIG: &str = ".toml";

/// Extension for app exe.
const EXT_APP_EXE: &str = ".vmexe";

/// Extension for proving key.
const EXT_APP_PK: &str = ".pk";

/// Circuit that implements functionality required to run e2e tests.
pub trait ProverTester {
    /// Prover type that is being tested.
    type Prover: ProverVerifier;

    /// Path to the corresponding circuit's project directory.
    const PATH_PROJECT_ROOT: &str;

    /// Prefix to use while naming app-specific data like app exe, app pk, etc.
    const PREFIX: &str;

    /// Build the ELF binary from the circuit program.
    fn build() -> eyre::Result<Elf> {
        let guest_opts = GuestOptions::default().with_features([FEATURE_SCROLL]);
        let elf = Sdk.build(guest_opts, Self::PATH_PROJECT_ROOT, &Default::default())?;
        Ok(elf)
    }

    /// Transpile the ELF into a VmExe.
    fn transpile(elf: Elf) -> eyre::Result<(AppConfig<SdkVmConfig>, PathBuf)> {
        let app_config = read_app_config(
            Path::new(DIR_OPENVM_ASSETS).join(format!("{}{EXT_APP_CONFIG}", Self::PREFIX)),
        )?;
        let app_exe = Sdk.transpile(elf, app_config.app_vm_config.transpiler())?;

        // Write exe to disc.
        let path_exe = Path::new(DIR_OPENVM_ASSETS).join(format!("{}{EXT_APP_EXE}", Self::PREFIX));
        write_exe_to_file(app_exe, &path_exe)?;

        Ok((app_config, path_exe))
    }

    /// Generate proving key and return path on disc.
    fn keygen(app_config: AppConfig<SdkVmConfig>) -> eyre::Result<PathBuf> {
        let app_pk = Sdk.app_keygen(app_config)?;

        // Write proving key to disc.
        let path_pk =
            Path::new(Self::PATH_PROJECT_ROOT).join(format!("{}{EXT_APP_PK}", Self::PREFIX));
        write_app_pk_to_file(app_pk, &path_pk)?;

        Ok(path_pk)
    }

    /// Generate proving task for test purposes.
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask>;
}
