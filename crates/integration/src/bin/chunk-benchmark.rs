#![feature(exit_status_error)]
//! Run `make bench-execute-chunk` to execute this benchmark.
use clap::Parser;
use openvm_benchmarks_prove::util::BenchmarkCli;
use openvm_benchmarks_utils::build_elf;
use openvm_circuit::openvm_stark_sdk::bench::run_with_metric_collection;
use openvm_sdk::config::{SdkVmBuilder, SdkVmConfig};
use scroll_zkvm_integration::testers::chunk::{
    ChunkProverTester, get_witness_from_env_or_builder, preset_chunk,
};
use scroll_zkvm_integration::{DIR_TESTRUN, ProverTester, WORKSPACE_ROOT};
use std::process::Command;
use std::{env, fs};

fn main() -> eyre::Result<()> {
    ChunkProverTester::setup(false)?;

    let output = DIR_TESTRUN.get().unwrap();
    fs::create_dir_all(output)?;
    let metrics_path = output.join("metrics.json");
    let symbol_path = output.join("guest.syms");
    unsafe {
        env::set_var("OUTPUT_PATH", &metrics_path);
        env::set_var("GUEST_SYMBOLS_PATH", &symbol_path);
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

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;

    run_with_metric_collection("OUTPUT_PATH", || {
        args.bench_from_exe::<SdkVmBuilder, _>(
            "chunk-circuit",
            app_vm_config,
            elf,
            ChunkProverTester::build_guest_input(&wit, std::iter::empty())?,
        )
    })?;

    // exec flamegraph generation script
    if args.profiling {
        Command::new("python3")
            .arg(WORKSPACE_ROOT.join("scripts").join("flamegraph.py"))
            .arg(metrics_path)
            .arg("--guest-symbols")
            .arg(symbol_path)
            .current_dir(output)
            .status()?
            .exit_ok()?;
    }

    Ok(())
}
