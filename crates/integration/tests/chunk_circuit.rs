use eyre::Ok;
use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester, read_block_witness_from_testdata},
    utils::testing_hardfork,
};
use scroll_zkvm_prover::{
    ChunkProverType, ProverType,
    setup::read_app_exe,
    task::{ProvingTask, chunk::ChunkProvingTask},
    utils::{self, vm::ExecutionResult},
};

fn exec_chunk(task: &ChunkProvingTask) -> eyre::Result<(ExecutionResult, u64)> {
    let (_path_app_config, app_config, path_exe) =
        ChunkProverTester::load_with_exe_fd("app.vmexe")?;
    let config = app_config.app_vm_config;
    let app_exe = read_app_exe(path_exe)?;

    let blk = task.block_witnesses[0].header.number;
    println!(
        "task block num: {}, block[0] idx: {}",
        task.block_witnesses.len(),
        blk
    );
    let stats = task.stats();
    println!("chunk stats {:#?}", stats);
    ChunkProverType::metadata_with_prechecks(task)?;
    println!("precheck finished");
    let stdin = task.build_guest_input()?;
    let exec_result = utils::vm::execute_guest(config, app_exe, &stdin)?;
    let cycle_count = exec_result.total_cycle as u64;
    let cycle_per_gas = cycle_count / stats.total_gas_used;
    println!(
        "blk {blk}, cycle {cycle_count}, gas {}, cycle-per-gas {cycle_per_gas}",
        stats.total_gas_used,
    );
    Ok((exec_result, stats.total_gas_used))
}

#[test]
fn test_cycle() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    // use rayon::prelude::*;

    let blocks = 1..=8;
    blocks.into_iter().try_for_each(|blk| -> eyre::Result<()> {
        let task = ChunkProvingTask {
            block_witnesses: vec![read_block_witness_from_testdata(blk)?],
            prev_msg_queue_hash: Default::default(),
            fork_name: testing_hardfork().to_string(),
        };
        let (exec_result, gas) = exec_chunk(&task)?;
        let cycle_per_gas = exec_result.total_cycle / gas;
        assert!(cycle_per_gas < 30);
        Ok(())
    })?;
    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let task = ChunkProverTester::gen_proving_task()?;
    exec_chunk(&task)?;

    Ok(())
}

#[test]
fn test_autofill_trie_nodes() -> eyre::Result<()> {
    use std::result::Result::Ok;
    ChunkProverTester::setup()?;

    let mut task: ChunkProvingTask = ChunkProverTester::gen_proving_task()?;
    task.block_witnesses.truncate(1);
    for index in [10, 13] {
        println!(
            "removing state at index {}: {:?}",
            index, task.block_witnesses[0].states[index]
        );
        let mut task = task.clone();
        task.block_witnesses[0].states.remove(index);

        let result = ChunkProverType::metadata_with_prechecks(&task);

        match result {
            Err(err_str) => {
                let err_str = format!("{}", err_str);
                // https://github.com/scroll-tech/scroll/blob/develop/crates/libzkp/src/tasks/chunk.rs#L155
                let pattern = r"SparseTrieError\(BlindedNode \{ path: Nibbles\((0x[0-9a-fA-F]+)\), hash: (0x[0-9a-fA-F]+) \}\)";
                let err_parse_re = regex::Regex::new(pattern)?;
                match err_parse_re.captures(&err_str) {
                    Some(caps) => {
                        let hash = caps[2].to_string();
                        println!("missing trie hash {hash}");
                        if index == 10 {
                            assert_eq!(
                                hash,
                                "0x3672d4a4951dbf05a8d18c33bd880a640aeb4dc1082bc96c489e3d658659c340"
                            );
                        }
                        if index == 13 {
                            assert_eq!(
                                hash,
                                "0x166a095be91b1f2ffc9d1a8abc0522264f67121086a4ea0b22a0a6bef07b000a"
                            );
                        }
                    }
                    None => {
                        println!("Cannot capture missing trie nodes");
                        panic!("Err msg: {}", err_str);
                    }
                }
            }
            Ok(_) => {
                panic!("Cannot capture missing trie nodes");
            }
        }
    }

    Ok(())
}

#[test]
fn test_execute_multi() -> eyre::Result<()> {
    // use rayon::iter::{IntoParallelIterator, ParallelIterator};

    MultiChunkProverTester::setup()?;

    // Initialize Rayon thread pool with 8 threads
    let parallel = 8;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel)
        .build()
        .unwrap();
    // Execute tasks in parallel
    let (total_gas, total_cycle) = pool.install(|| {
        let tasks = MultiChunkProverTester::gen_multi_proving_tasks().unwrap();
        let init = (0u64, 0u64);
        let adder = |(gas1, cycle1): (u64, u64),
                     (gas2, cycle2): (u64, u64)| {
            (gas1 + gas2, cycle1 + cycle2)
        };
        tasks
            .into_iter()
            .map(|task| -> (u64, u64) {
                let (exec_result, gas) = exec_chunk(&task).unwrap();
                (gas, exec_result.total_cycle)
            })
            .fold(init, adder)
    });

    println!(
        "Total gas: {}, Total cycles: {}, Average cycle/gas: {}",
        total_gas,
        total_cycle,
        total_cycle as f64 / total_gas as f64,
    );

    Ok(())
}

#[test]
fn guest_profiling() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    let (path_app_config, _, path_app_exe) = ChunkProverTester::load()?;

    let config = scroll_zkvm_prover::ProverConfig {
        path_app_exe,
        path_app_config,
        ..Default::default()
    };
    let chunk_prover =
        scroll_zkvm_prover::Prover::<scroll_zkvm_prover::ChunkProverType>::setup(config)?;

    let task = ChunkProverTester::gen_proving_task()?;
    let stdin = task.build_guest_input()?;
    let total_cycles = chunk_prover.execute_and_check(&stdin)?;

    println!(
        "scroll-zkvm-integration(chunk-circuit): total cycles = {:?}",
        total_cycles
    );

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
