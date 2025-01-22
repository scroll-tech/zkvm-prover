use std::path::{Path, PathBuf};

use openvm_build::GuestOptions;
use openvm_sdk::{
    Sdk,
    config::{AppConfig, SdkVmConfig},
    fs::{write_app_pk_to_file, write_exe_to_file},
};
use openvm_transpiler::elf::Elf;
use scroll_zkvm_prover::{ProverVerifier, setup::read_app_config};
use tracing::{Level, instrument};
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

pub mod testers;

/// Feature to enable while building the guest program.
const FEATURE_SCROLL: &str = "scroll";

/// Path to store release assets, root directory of zkvm-prover repository.
const DIR_OPENVM_ASSETS: &str = "./../../.openvm";

/// Directory to store proofs on disc.
const DIR_PROOFS: &str = "proofs";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// File descriptor for proving key.
const FD_APP_PK: &str = "app.pk";

/// Circuit that implements functionality required to run e2e tests.
pub trait ProverTester {
    /// Prover type that is being tested.
    type Prover: ProverVerifier;

    /// Path to the corresponding circuit's project directory.
    const PATH_PROJECT_ROOT: &str;

    /// Prefix to use while naming app-specific data like app exe, app pk, etc.
    const ASSETS_DIR: &str;

    /// Build the ELF binary from the circuit program.
    #[instrument("ProverTester::build", fields(project_root = Self::PATH_PROJECT_ROOT))]
    fn build() -> eyre::Result<Elf> {
        let guest_opts = GuestOptions::default().with_features([FEATURE_SCROLL]);
        let elf = Sdk.build(guest_opts, Self::PATH_PROJECT_ROOT, &Default::default())?;
        Ok(elf)
    }

    /// Transpile the ELF into a VmExe.
    #[instrument(
        "ProverTester::transpile",
        skip_all,
        fields(path_app_config, path_app_exe)
    )]
    fn transpile(elf: Elf) -> eyre::Result<(AppConfig<SdkVmConfig>, PathBuf)> {
        // Create the assets directory to store app-specific assets.
        //
        // Ignore error as the dir could already exist, in which case we can simply proceed.
        let path_assets = Path::new(DIR_OPENVM_ASSETS).join(Self::ASSETS_DIR);
        let _ = std::fs::create_dir(&path_assets);

        // First read the app config specified in the project's root directory.
        let path_app_config = Path::new(Self::PATH_PROJECT_ROOT).join(FD_APP_CONFIG);
        let app_config = read_app_config(&path_app_config)?;

        // Copy the app config to assets directory for convenience of export/release.
        //
        // - <openvm-assets>/<assets-dir>/openvm.toml
        let path_dup_app_config = path_assets.join(FD_APP_CONFIG);
        std::fs::copy(&path_app_config, &path_dup_app_config)?;

        // Transpile ELF to openvm executable.
        let app_exe = Sdk.transpile(elf, app_config.app_vm_config.transpiler())?;

        // Write exe to disc.
        let path_app_exe = path_assets.join(FD_APP_EXE);
        write_exe_to_file(app_exe, &path_app_exe)?;

        Ok((app_config, path_app_exe))
    }

    /// Generate proving key and return path on disc.
    #[instrument("ProverTester::keygen", skip_all, fields(path_app_pk))]
    fn keygen(app_config: AppConfig<SdkVmConfig>) -> eyre::Result<PathBuf> {
        let app_pk = Sdk.app_keygen(app_config)?;

        // Write proving key to disc.
        let path_app_pk = Path::new(DIR_OPENVM_ASSETS)
            .join(Self::ASSETS_DIR)
            .join(FD_APP_PK);
        write_app_pk_to_file(app_pk, &path_app_pk)?;

        Ok(path_app_pk)
    }

    /// Generate proving task for test purposes.
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask>;

    /// Generate multiple proving tasks for test purposes.
    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverVerifier>::ProvingTask>>
    {
        unimplemented!()
    }
}

/// The outcome of a successful prove-verify run.
pub struct ProveVerifyOutcome<T, P> {
    /// Single or multiple proving tasks.
    pub tasks: Vec<T>,
    /// Verified proofs for the proving tasks.
    pub proofs: Vec<P>,
}

impl<T: Clone, P: Clone> ProveVerifyOutcome<T, P> {
    pub fn single(task: T, proof: P) -> Self {
        Self {
            tasks: vec![task],
            proofs: vec![proof],
        }
    }

    pub fn multi(tasks: &[T], proofs: &[P]) -> Self {
        Self {
            tasks: tasks.to_vec(),
            proofs: proofs.to_vec(),
        }
    }
}

/// Setup test environment
pub fn setup() -> eyre::Result<()> {
    let filters = tracing_subscriber::filter::Targets::new()
        .with_target("scroll_zkvm_prover", Level::INFO)
        .with_target("scroll_zkvm_integration", Level::DEBUG);

    let fmt_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_span_events(FmtSpan::CLOSE);

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(filters)
        .try_init()?;

    Ok(())
}

/// Alias for convenience.
type ProveVerifyRes<T> = eyre::Result<
    ProveVerifyOutcome<
        <<T as ProverTester>::Prover as ProverVerifier>::ProvingTask,
        <<T as ProverTester>::Prover as ProverVerifier>::Proof,
    >,
>;

/// End-to-end test for a single proving task.
#[instrument(name = "prove_verify_single", skip_all)]
pub fn prove_verify_single<T>(
    task: Option<<T::Prover as ProverVerifier>::ProvingTask>,
) -> ProveVerifyRes<T>
where
    T: ProverTester,
    <T::Prover as ProverVerifier>::ProvingTask: Clone,
    <T::Prover as ProverVerifier>::Proof: Clone,
{
    // Build the ELF binary from the circuit program.
    let elf = T::build()?;

    // Transpile the ELF into a VmExe.
    let (app_config, path_exe) = T::transpile(elf)?;

    // Generate application proving key and get path on disc.
    let path_pk = T::keygen(app_config)?;

    // Setup prover.
    let cache_dir = Path::new(DIR_OPENVM_ASSETS)
        .join(DIR_PROOFS)
        .join(<T as ProverTester>::ASSETS_DIR);
    let _ = std::fs::create_dir_all(&cache_dir);
    let prover = <T as ProverTester>::Prover::setup(&path_exe, &path_pk, Some(&cache_dir))?;

    // Generate proving task for the circuit.
    let task = task.unwrap_or(T::gen_proving_task()?);

    // Construct root proof for the circuit.
    let proof = prover.gen_proof(&task)?;

    // Verify proof.
    prover.verify_proof(&proof)?;

    Ok(ProveVerifyOutcome::single(task, proof))
}

/// End-to-end test for multiple proving tasks of the same prover.
#[instrument(name = "prove_verify_multi", skip_all)]
pub fn prove_verify_multi<T>(
    tasks: Option<&[<T::Prover as ProverVerifier>::ProvingTask]>,
) -> ProveVerifyRes<T>
where
    T: ProverTester,
    <T::Prover as ProverVerifier>::ProvingTask: Clone,
    <T::Prover as ProverVerifier>::Proof: Clone,
{
    // Build the ELF binary from the circuit program.
    let elf = T::build()?;

    // Transpile the ELF into a VmExe.
    let (app_config, path_exe) = T::transpile(elf)?;

    // Generate application proving key and get path on disc.
    let path_pk = T::keygen(app_config)?;

    // Setup prover.
    let cache_dir = Path::new(DIR_OPENVM_ASSETS)
        .join(DIR_PROOFS)
        .join(<T as ProverTester>::ASSETS_DIR);
    let _ = std::fs::create_dir_all(&cache_dir);
    let prover = <T as ProverTester>::Prover::setup(&path_exe, &path_pk, Some(&cache_dir))?;

    // Generate proving task for the circuit.
    let tasks = tasks.map_or_else(|| T::gen_multi_proving_tasks(), |tasks| Ok(tasks.to_vec()))?;

    // For each of the tasks, generate and verify proof.
    let proofs = tasks
        .iter()
        .map(|task| {
            let proof = prover.gen_proof(task)?;
            prover.verify_proof(&proof)?;
            Ok(proof)
        })
        .collect::<eyre::Result<Vec<<T::Prover as ProverVerifier>::Proof>>>()?;

    Ok(ProveVerifyOutcome::multi(&tasks, &proofs))
}
