use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester},
};

#[test]
fn setup() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let elf = ChunkProverTester::build()?;

    let (app_config, _) = ChunkProverTester::transpile(elf)?;

    ChunkProverTester::keygen(app_config)?;

    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    let elf = MultiChunkProverTester::build()?;

    let (app_config, exe_path) = MultiChunkProverTester::transpile(elf)?;

    for task in MultiChunkProverTester::gen_multi_proving_tasks()? {
        MultiChunkProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let _outcome = prove_verify_single::<ChunkProverTester>(None)?;

    Ok(())
}

#[test]
fn multi_chunk() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    let _outcome = prove_verify_multi::<MultiChunkProverTester>(None)?;

    Ok(())
}
