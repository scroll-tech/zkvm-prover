use std::path::{Path, PathBuf};

use openvm_build::GuestOptions;
use openvm_sdk::{
    Sdk,
    config::{AppConfig, SdkVmConfig},
    fs::{write_app_pk_to_file, write_exe_to_file},
};
use openvm_transpiler::elf::Elf;
use scroll_zkvm_prover::{ProverVerifier, read_app_config};

/// Feature to enable while building the guest program.
const FEATURE_SCROLL: &str = "scroll";

/// Directory where openvm related configs and build results are stored in disc.
const DIR_OPENVM: &str = ".openvm";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// File descriptor for proving key.
const FD_APP_PK: &str = "app.pk";

/// Circuit that implements functionality required to run e2e tests.
pub trait Circuit {
    type Prover: ProverVerifier;

    const PATH_PROJECT_ROOT: &str;

    const PREFIX: &str;

    /// Build the ELF binary from the circuit program.
    fn build() -> eyre::Result<Elf> {
        let guest_opts = GuestOptions::default().with_features([FEATURE_SCROLL]);
        let elf = Sdk.build(guest_opts, Self::PATH_PROJECT_ROOT, &Default::default())?;
        Ok(elf)
    }

    /// Transpile the ELF into a VmExe.
    fn transpile(elf: Elf) -> eyre::Result<(AppConfig<SdkVmConfig>, PathBuf)> {
        let app_config = read_app_config(Path::new(Self::PATH_PROJECT_ROOT).join(FD_APP_CONFIG))?;
        let app_exe = Sdk.transpile(elf, app_config.app_vm_config.transpiler())?;

        // Write exe to disc.
        let path_exe = Path::new(Self::PATH_PROJECT_ROOT)
            .join(DIR_OPENVM)
            .join(FD_APP_EXE);
        write_exe_to_file(app_exe, &path_exe)?;

        Ok((app_config, path_exe))
    }

    /// Generate proving key and return path on disc.
    fn keygen(app_config: AppConfig<SdkVmConfig>) -> eyre::Result<PathBuf> {
        let app_pk = Sdk.app_keygen(app_config)?;

        // Write proving key to disc.
        let path_pk = Path::new(Self::PATH_PROJECT_ROOT)
            .join(DIR_OPENVM)
            .join(FD_APP_PK);
        write_app_pk_to_file(app_pk, &path_pk)?;

        Ok(path_pk)
    }

    /// Generate some witness for test purposes.
    fn gen_witness() -> eyre::Result<<Self::Prover as ProverVerifier>::Witness>;
}
