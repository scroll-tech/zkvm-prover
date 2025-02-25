use std::path::Path;

use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::{
        PATH_TESTDATA,
        chunk::{ChunkProverTester, MultiChunkProverTester, read_block_witness},
    },
};
use scroll_zkvm_prover::{
    ChunkProver, ChunkProverType, ProverType,
    task::{ProvingTask, chunk::ChunkProvingTask},
};

#[test]
fn test_cycle() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let (path_app_config, _app_config, path_exe) = ChunkProverTester::load()?;
    use rayon::prelude::*;

    let blocks = 1..=8;
    blocks
        .into_par_iter()
        .try_for_each(|blk| -> eyre::Result<()> {
            let task = ChunkProvingTask {
                block_witnesses: vec![read_block_witness(
                    blk,
                    &Path::new(PATH_TESTDATA).join("euclid_v2"),
                )?],
                prev_msg_queue_hash: Default::default(),
            };

            let stats = task.stats();
            ChunkProverType::metadata_with_prechecks(&task)?;
            let prover = ChunkProver::setup(&path_exe, &path_app_config, None)?;
            let profile = false;
            let (cycle_count, _) = prover.execute_guest(&task.build_guest_input()?, profile)?;
            let cycle_per_gas = cycle_count / stats.total_gas_used;
            println!("chunk stats {:#?}", stats);
            println!("total cycle count {}", cycle_count);
            println!("cycle count per gas {}, blk idx {}", cycle_per_gas, blk);
            Ok(())
        })?;
    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let (path_app_config, _app_config, path_exe) = ChunkProverTester::load()?;
    let task = ChunkProverTester::gen_proving_task()?;
    let stats = task.stats();
    println!("chunk stats {:#?}", stats);
    ChunkProverType::metadata_with_prechecks(&task)?;
    let prover = ChunkProver::setup(&path_exe, &path_app_config, None)?;
    let profile = false;
    let (cycle_count, _) = prover.execute_guest(&task.build_guest_input()?, profile)?;
    let cycle_per_gas = cycle_count / stats.total_gas_used;
    println!("total cycle count {}", cycle_count);
    println!("cycle count per gas {}", cycle_per_gas);
    Ok(())
}

#[test]
fn test_execute_multi() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    let (_, app_config, exe_path) = MultiChunkProverTester::load()?;

    for task in MultiChunkProverTester::gen_multi_proving_tasks()? {
        MultiChunkProverTester::execute(app_config.clone(), &task, exe_path.clone())?;
    }

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    prove_verify_single::<ChunkProverTester>(None)?;

    Ok(())
}

#[test]
fn setup_prove_verify_multi() -> eyre::Result<()> {
    MultiChunkProverTester::setup()?;

    prove_verify_multi::<MultiChunkProverTester>(None)?;

    Ok(())
}
