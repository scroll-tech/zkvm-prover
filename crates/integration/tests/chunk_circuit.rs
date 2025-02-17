use openvm_stark_sdk::bench::run_with_metric_collection;
use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};

#[test]
fn test_execute() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    let elf = MultiChunkProverTester::build()?;

    let (_, app_config, exe_path) = MultiChunkProverTester::transpile(elf, None)?;

    for task in MultiChunkProverTester::gen_multi_proving_tasks()? {
        MultiChunkProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    run_with_metric_collection("OUTPUT_PATH", || -> eyre::Result<()> {
        prove_verify_single::<ChunkProverTester>(None)?;
        Ok(())
    })
}

#[test]
fn setup_prove_verify_multi() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    run_with_metric_collection("OUTPUT_PATH", || -> eyre::Result<()> {
        prove_verify_multi::<MultiChunkProverTester>(None)?;
        Ok(())
    })
}
