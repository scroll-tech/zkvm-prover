use std::{
    path::{Path, PathBuf},
    process,
};

use once_cell::sync::OnceCell;
use openvm_build::GuestOptions;
use openvm_native_recursion::halo2::EvmProof;
use openvm_sdk::{
    Sdk, StdIn,
    config::{AppConfig, SdkVmConfig},
    fs::write_exe_to_file,
    verifier::root::types::RootVmVerifierInput,
};
use openvm_transpiler::elf::Elf;
use scroll_zkvm_prover::{
    ProverType, SC, WrappedProof,
    setup::{read_app_config, read_app_exe},
    task::ProvingTask,
};
use tracing::instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt};

pub mod testers;

pub mod utils;

/// Feature to enable while building the guest program.
const FEATURE_SCROLL: &str = "scroll";

/// Path to store release assets, root directory of zkvm-prover repository.
const DIR_OUTPUT: &str = "./../../.output";

/// Directory to store proofs on disc.
const DIR_PROOFS: &str = "proofs";

/// File descriptor for app openvm config.
const FD_APP_CONFIG: &str = "openvm.toml";

/// File descriptor for app exe.
const FD_APP_EXE: &str = "app.vmexe";

/// Environment variable used to set the test-run's output directory for assets.
const ENV_OUTPUT_DIR: &str = "OUTPUT_DIR";

/// Every test run will write assets to a new directory.
///
/// Possibly one of the following:
/// - <DIR_OUTPUT>/chunk-tests-{timestamp}
/// - <DIR_OUTPUT>/batch-tests-{timestamp}
/// - <DIR_OUTPUT>/bundle-tests-{timestamp}
static DIR_TESTRUN: OnceCell<PathBuf> = OnceCell::new();

/// Circuit that implements functionality required to run e2e tests.
pub trait ProverTester {
    /// Prover type that is being tested.
    type Prover: ProverType;

    /// Path to the corresponding circuit's project directory.
    const PATH_PROJECT_ROOT: &str;

    /// Prefix to use while naming app-specific data like app exe, app pk, etc.
    const DIR_ASSETS: &str;

    /// Setup directory structure for the test suite.
    fn setup() -> eyre::Result<()> {
        // Setup tracing subscriber.
        setup_logger()?;

        // If user has set an output directory, use it.
        let dir_testrun = if let Ok(env_dir) = std::env::var(ENV_OUTPUT_DIR) {
            let dir = Path::new(&env_dir);
            if std::fs::exists(dir).is_err() {
                tracing::error!("OUTPUT_DIR={dir:?} not found");
                process::exit(1);
            }
            dir.into()
        } else {
            // Create the <OUTPUT>/{DIR_ASSETS}-test-{timestamp} for test-run.
            let testrun = format!(
                "{}-tests-{}",
                Self::DIR_ASSETS,
                chrono::Utc::now().format("%Y%m%d_%H%M%S"),
            );
            Path::new(DIR_OUTPUT).join(testrun)
        };

        // Set the path for the current test-run.
        DIR_TESTRUN
            .set(dir_testrun)
            .map_err(|dir| eyre::eyre!("could not set test-run dir: {dir:?}"))?;

        Ok(())
    }

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
    fn transpile(elf: Elf) -> eyre::Result<(PathBuf, AppConfig<SdkVmConfig>, PathBuf)> {
        // Create the assets dir if not already present.
        let path_assets = DIR_TESTRUN
            .get()
            .ok_or(eyre::eyre!("missing assets dir"))?
            .join(Self::DIR_ASSETS);
        std::fs::create_dir_all(&path_assets)?;

        // First read the app config specified in the project's root directory.
        let path_app_config = Path::new(Self::PATH_PROJECT_ROOT).join(FD_APP_CONFIG);
        let mut app_config = read_app_config(&path_app_config)?;

        // FIXME: additional app config for batch and bundle guest program.
        if Self::DIR_ASSETS != "chunk" {
            app_config.app_vm_config.castf = Some(openvm_native_circuit::CastFExtension);
        }

        // Copy the app config to assets directory for convenience of export/release.
        //
        // - <openvm-assets>/<assets-dir>/openvm.toml
        let path_dup_app_config = path_assets.join(FD_APP_CONFIG);
        std::fs::copy(&path_app_config, &path_dup_app_config)?;

        // Transpile ELF to openvm executable.
        let mut transpiler = app_config.app_vm_config.transpiler();
        if Self::DIR_ASSETS != "chunk" {
            transpiler =
                transpiler.with_extension(openvm_native_transpiler::LongFormTranspilerExtension);
        }
        let app_exe = Sdk.transpile(elf, transpiler)?;

        // Write exe to disc.
        let path_app_exe = path_assets.join(FD_APP_EXE);
        write_exe_to_file(app_exe, &path_app_exe)?;

        Ok((path_app_config, app_config, path_app_exe))
    }

    /// Generate proving task for test purposes.
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask>;

    /// Generate multiple proving tasks for test purposes.
    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        unimplemented!("must be implemented by MultiTester");
    }

    /// Light weight testing to simply execute the vm program for test
    #[instrument("ProverTester::execute", skip_all, fields(task_id))]
    fn execute(
        app_config: AppConfig<SdkVmConfig>,
        task: &<Self::Prover as ProverType>::ProvingTask,
        exe_path: impl AsRef<Path>,
    ) -> eyre::Result<()> {
        let serialized = task.to_witness_serialized()?;

        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);

        let pi = Sdk.execute(read_app_exe(exe_path)?, app_config.app_vm_config, stdin)?;
        println!("pi: {pi:?}");

        Ok(())
    }

    fn execute_with_proving_task(
        app_config: AppConfig<SdkVmConfig>,
        exe_path: impl AsRef<Path>,
    ) -> eyre::Result<()> {
        Self::execute(app_config, &Self::gen_proving_task()?, exe_path)
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
fn setup_logger() -> eyre::Result<()> {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_span_events(FmtSpan::CLOSE);

    #[cfg(feature = "limit-logs")]
    {
        let filters = tracing_subscriber::filter::Targets::new()
            .with_target("scroll_zkvm_prover", tracing::Level::INFO)
            .with_target("scroll_zkvm_integration", tracing::Level::DEBUG);

        tracing_subscriber::registry()
            .with(fmt_layer)
            .with(filters)
            .try_init()?;
    }

    #[cfg(not(feature = "limit-logs"))]
    {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::from_default_env())
            .with(fmt_layer)
            .try_init()?;
    }

    Ok(())
}

/// Alias for convenience.
type ProveVerifyRes<T> = eyre::Result<
    ProveVerifyOutcome<
        <<T as ProverTester>::Prover as ProverType>::ProvingTask,
        WrappedProof<
            <<T as ProverTester>::Prover as ProverType>::ProofMetadata,
            RootVmVerifierInput<SC>,
        >,
    >,
>;

/// Alias for convenience.
type ProveVerifyEvmRes<T> = eyre::Result<
    ProveVerifyOutcome<
        <<T as ProverTester>::Prover as ProverType>::ProvingTask,
        WrappedProof<<<T as ProverTester>::Prover as ProverType>::ProofMetadata, EvmProof>,
    >,
>;

/// End-to-end test for a single proving task.
#[instrument(name = "prove_verify_single", skip_all)]
pub fn prove_verify_single<T>(
    task: Option<<T::Prover as ProverType>::ProvingTask>,
) -> ProveVerifyRes<T>
where
    T: ProverTester,
    <T::Prover as ProverType>::ProvingTask: Clone,
    <T::Prover as ProverType>::ProofMetadata: Clone,
    <T::Prover as ProverType>::ProofType: Clone,
{
    // Build the ELF binary from the circuit program.
    let elf = T::build()?;

    // Transpile the ELF into a VmExe.
    let (path_app_config, _, path_exe) = T::transpile(elf)?;

    // Setup prover.
    let cache_dir = DIR_TESTRUN
        .get()
        .ok_or(eyre::eyre!("missing assets dir"))?
        .join(T::DIR_ASSETS)
        .join(DIR_PROOFS);
    std::fs::create_dir_all(&cache_dir)?;
    let prover = scroll_zkvm_prover::Prover::<T::Prover>::setup(
        &path_exe,
        &path_app_config,
        Some(&cache_dir),
    )?;

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
    tasks: Option<&[<T::Prover as ProverType>::ProvingTask]>,
) -> ProveVerifyRes<T>
where
    T: ProverTester,
    <T::Prover as ProverType>::ProvingTask: Clone,
    <T::Prover as ProverType>::ProofMetadata: Clone,
    <T::Prover as ProverType>::ProofType: Clone,
{
    // Build the ELF binary from the circuit program.
    let elf = T::build()?;

    // Transpile the ELF into a VmExe.
    let (path_app_config, _, path_exe) = T::transpile(elf)?;

    // Setup prover.
    let cache_dir = DIR_TESTRUN
        .get()
        .ok_or(eyre::eyre!("missing assets dir"))?
        .join(T::DIR_ASSETS)
        .join(DIR_PROOFS);
    std::fs::create_dir_all(&cache_dir)?;
    let prover = scroll_zkvm_prover::Prover::<T::Prover>::setup(
        &path_exe,
        &path_app_config,
        Some(&cache_dir),
    )?;

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
        .collect::<eyre::Result<
            Vec<WrappedProof<<T::Prover as ProverType>::ProofMetadata, RootVmVerifierInput<SC>>>,
        >>()?;

    Ok(ProveVerifyOutcome::multi(&tasks, &proofs))
}

/// End-to-end test for a single proving task to generate an EVM-verifiable SNARK proof.
#[instrument(name = "prove_verify_single_evm", skip_all)]
pub fn prove_verify_single_evm<T>(
    task: Option<<T::Prover as ProverType>::ProvingTask>,
) -> ProveVerifyEvmRes<T>
where
    T: ProverTester,
    <T::Prover as ProverType>::ProvingTask: Clone,
    <T::Prover as ProverType>::ProofMetadata: Clone,
    <T::Prover as ProverType>::ProofType: Clone,
{
    // Build the ELF binary from the circuit program.
    let elf = T::build()?;

    // Transpile the ELF into a VmExe.
    let (path_app_config, _, path_exe) = T::transpile(elf)?;

    // Setup prover.
    let path_assets = DIR_TESTRUN
        .get()
        .ok_or(eyre::eyre!("missing testrun dir"))?
        .join(T::DIR_ASSETS);
    let cache_dir = path_assets.join(DIR_PROOFS);
    std::fs::create_dir_all(&cache_dir)?;
    let prover = scroll_zkvm_prover::Prover::<T::Prover>::setup(
        &path_exe,
        &path_app_config,
        Some(&cache_dir),
    )?;

    // Generate proving task for the circuit.
    let task = task.unwrap_or(T::gen_proving_task()?);

    // Construct root proof for the circuit.
    let proof = prover.gen_proof_evm(&task)?;

    // Verify proof.
    prover.verify_proof_evm(&proof)?;

    // The structure of the halo2-proof's instances is:
    // - 12 instances for accumulator
    // - 2 instances for digests (MUST be checked on-chain)
    // - 32 instances for pi_hash (bundle_pi_hash)
    //
    // We write the 2 digests to disc.
    let digest_1 = proof.proof.instances[0][12];
    let digest_2 = proof.proof.instances[0][13];
    scroll_zkvm_prover::utils::write(
        path_assets.join("digest_1"),
        &digest_1.to_bytes().into_iter().rev().collect::<Vec<u8>>(),
    )?;
    scroll_zkvm_prover::utils::write(
        path_assets.join("digest_2"),
        &digest_2.to_bytes().into_iter().rev().collect::<Vec<u8>>(),
    )?;

    Ok(ProveVerifyOutcome::single(task, proof))
}
