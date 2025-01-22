use scroll_zkvm_integration::{
    prove_verify_multi, prove_verify_single, setup_logger,
    testers::{batch::BatchProverTester, chunk::MultiChunkProverTester},
};
use scroll_zkvm_prover::{utils::read_json, setup::read_app_config, task::batch::BatchProvingTask};
use openvm_sdk::{
    config::{AggConfig, AppConfig, SdkVmConfig},
    prover::AppProver,
    Sdk, StdIn,
};
use openvm_transpiler::{openvm_platform::memory::MEM_SIZE, elf::Elf};
use tracing::info;

#[test]
fn batch_simple_execution() -> eyre::Result<()> {
    setup()?;

    // read task
    let task : BatchProvingTask = read_json("testdata/batch-task-with-blob.json")?;
    info!("benching task for batch {}", task.batch_header.batch_index);

    // suppose we are under `integration` path
    let app_config = read_app_config("../circuits/batch-circuit/openvm.toml")?;
    let vm_config = app_config.app_vm_config;

    // ANCHOR_END: vm_config

    // to import example guest code in crate replace `target_path` for:
    // ```
    // use std::path::PathBuf;
    //
    // let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).to_path_buf();
    // path.push("guest");
    // let target_path = path.to_str().unwrap();
    // ```
    // ANCHOR: build
    // 1. Build the VmConfig with the extensions needed.
    let sdk = Sdk;
    // 2a. Build the ELF with guest options and a target filter (skipped, simply read elf).


    let elf_bytes = std::fs::read("../../target/riscv32im-risc0-zkvm-elf/release/batch-circuit")?;
    let elf = Elf::decode(&elf_bytes, MEM_SIZE as u32)?;    
    // ANCHOR_END: build

    // ANCHOR: transpilation
    // 3. Transpile the ELF into a VmExe
    let exe = sdk.transpile(elf, vm_config.transpiler())?;

    // ANCHOR: execution
    // 4. Format your input into StdIn
    let mut stdin = StdIn::default();
    stdin.write_bytes(&task.serialized_into());

    let start_t = std::time::Instant::now();
    let output = sdk.execute(exe.clone(), vm_config.clone(), stdin.clone())?;
    info!("complete in {:?}, public values output: {:?}", start_t.elapsed(), output);

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    setup_logger()?;

    let _outcome = prove_verify_single::<BatchProverTester>(None)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    setup_logger()?;

    let outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;
    let (_chunk_tasks, _chunk_proofs) = (outcome.tasks, outcome.proofs);

    // TODO: construct batch task from chunk tasks and chunk proofs.
    let batch_task = None;
    let _outcome = prove_verify_single::<BatchProverTester>(batch_task)?;

    Ok(())
}
