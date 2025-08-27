use std::{env, fs};
use clap::Parser;
use openvm_benchmarks_prove::util::BenchmarkCli;
use openvm_build::GuestOptions;
use openvm_circuit::openvm_stark_sdk::bench::run_with_metric_collection;
use openvm_sdk::config::{AppConfig, SdkVmConfig, SdkVmCpuBuilder};
use openvm_sdk::{Sdk, StdIn};
use scroll_zkvm_integration::testers::chunk::{get_witness_from_env_or_builder, preset_chunk, ChunkProverTester};
use scroll_zkvm_integration::{PartialProvingTask, ProverTester, DIR_TESTRUN, WORKSPACE_ROOT};

fn main() -> eyre::Result<()> {
    ChunkProverTester::setup(false)?;

    let output = DIR_TESTRUN.get().unwrap();
    fs::create_dir_all(output)?;
    unsafe {
        env::set_var("OUTPUT_PATH", output.join("metrics.json"));
        env::set_var("GUEST_SYMBOLS_PATH", output.join("guest.syms"));
    }

    let args: BenchmarkCli = BenchmarkCli::parse();

    let app_config: AppConfig<SdkVmConfig> =
        toml::from_str(include_str!("../../../circuits/chunk-circuit/openvm.toml"))?;
    let sdk = Sdk::new(app_config.clone())?;
    let elf = sdk.build(
        GuestOptions::default().with_profile(if args.profiling {
            "profiling"
        } else {
            "maxperf"
        }.to_string()),
        WORKSPACE_ROOT.join("crates").join("circuits").join("chunk-circuit"),
        &Default::default(),
        None
    )?;

    let mut stdin = StdIn::default();

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    wit.write_guest_input(&mut stdin)?;

    run_with_metric_collection("OUTPUT_PATH", || {
        args.bench_from_exe::<SdkVmCpuBuilder, _>(
            "chunk-circuit",
            app_config.app_vm_config,
            elf,
            stdin,
        )
    })
}
