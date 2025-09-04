//! To get flamegraphs, following instructions are needed:
//!
//! 1. run in `crates/integration` dir:
//!
//!   `OPENVM_RUST_TOOLCHAIN=nightly-2025-08-18 cargo run --release --bin chunk-benchmark --features perf-metrics -- --profiling`
//! 2. run in `.output/chunk-tests-*_*`:
//!
//!   `python <path to openvm repo>/ci/scripts/metric_unify/flamegraph.py metrics.json --guest-symbols guest.syms`
//! 3. get flamegraphs in `.bench_metrics/flamegraphs`
use clap::Parser;
use openvm_benchmarks_prove::util::BenchmarkCli;
use openvm_benchmarks_utils::build_elf;
use openvm_circuit::openvm_stark_sdk::bench::run_with_metric_collection;
use openvm_sdk::StdIn;
use openvm_sdk::config::{SdkVmConfig, SdkVmBuilder};
use scroll_zkvm_integration::testers::chunk::{
    ChunkProverTester, get_witness_from_env_or_builder, preset_chunk,
};
use scroll_zkvm_integration::{DIR_TESTRUN, PartialProvingTask, ProverTester, WORKSPACE_ROOT};
use std::{env, fs};

fn main() -> eyre::Result<()> {
    ChunkProverTester::setup(false)?;

    let output = DIR_TESTRUN.get().unwrap();
    fs::create_dir_all(output)?;
    unsafe {
        env::set_var("OUTPUT_PATH", output.join("metrics.json"));
        env::set_var("GUEST_SYMBOLS_PATH", output.join("guest.syms"));
    }

    let args: BenchmarkCli = BenchmarkCli::parse();

    let app_vm_config =
        SdkVmConfig::from_toml(include_str!("../../../circuits/chunk-circuit/openvm.toml"))?
            .app_vm_config;
    let project_path = WORKSPACE_ROOT
        .join("crates")
        .join("circuits")
        .join("chunk-circuit");
    let current_dir = env::current_dir()?;
    env::set_current_dir(&project_path)?;
    let elf = build_elf(
        &project_path,
        if args.profiling {
            "profiling"
        } else {
            "maxperf"
        },
    )?;
    env::set_current_dir(current_dir)?;

    let mut stdin = StdIn::default();

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    wit.write_guest_input(&mut stdin)?;

    run_with_metric_collection("OUTPUT_PATH", || {
        args.bench_from_exe::<SdkVmBuilder, _>("chunk-circuit", app_vm_config, elf, stdin)
    })
}
