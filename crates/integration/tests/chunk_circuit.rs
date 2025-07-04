use eyre::{Context, ContextCompat};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use scroll_zkvm_integration::{
    ProverTester, prove_verify_multi, prove_verify_single,
    testers::chunk::{ChunkProverTester, MultiChunkProverTester, read_block_witness_from_testdata},
    utils::get_rayon_threads,
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
    let exec_result = utils::vm::execute_guest(config, app_exe, &stdin, &Default::default())?;
    let cycle_count = exec_result.total_cycle as u64;
    let cycle_per_gas = cycle_count / stats.total_gas_used;
    println!(
        "blk {blk}, cycle {cycle_count}, gas {}, cycle-per-gas {cycle_per_gas}, tick-per-gas {}",
        stats.total_gas_used,
        exec_result.total_tick as u64 / stats.total_gas_used,
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
            fork_name: if cfg!(feature = "euclidv2") {
                String::from("euclidv2")
            } else {
                String::from("euclidv1")
            },
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

fn execute_multi(
    proving_tasks: Vec<ChunkProvingTask>,
) -> impl FnOnce() -> (u64, u64, u64) + Send + Sync + 'static {
    || {
        proving_tasks
            .into_par_iter()
            .map(|task| -> (u64, u64, u64) {
                let (exec_result, gas) = exec_chunk(&task).unwrap();
                (gas, exec_result.total_cycle, exec_result.total_tick)
            })
            .reduce(
                || (0u64, 0u64, 0u64),
                |(gas1, cycle1, tick1): (u64, u64, u64), (gas2, cycle2, tick2): (u64, u64, u64)| {
                    (gas1 + gas2, cycle1 + cycle2, tick1 + tick2)
                },
            )
    }
}

#[test]
fn test_execute_multi() -> eyre::Result<()> {
    // use rayon::iter::{IntoParallelIterator, ParallelIterator};

    MultiChunkProverTester::setup()?;

    // Initialize Rayon thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_rayon_threads())
        .build()
        .unwrap();
    // Execute tasks in parallel
    let (total_gas, total_cycle, total_tick) = pool.install(execute_multi(
        MultiChunkProverTester::gen_multi_proving_tasks().unwrap(),
    ));

    println!(
        "Total gas: {}, Total cycles: {}, Average cycle/gas: {}, Average tick/gas: {}",
        total_gas,
        total_cycle,
        total_cycle as f64 / total_gas as f64,
        total_tick as f64 / total_gas as f64,
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
    let total_cycles = chunk_prover.execute_and_check(&stdin, false)?;

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

#[tokio::test]
async fn test_scanner() -> eyre::Result<()> {
    use alloy_provider::{Provider, ProviderBuilder};
    use alloy_rpc_client::ClientBuilder;
    use alloy_transport::layers::{RetryBackoffLayer, ThrottleLayer};
    use sbv_primitives::types::Network;
    use sbv_utils::rpc::ProviderExt;
    use std::env;
    use url::Url;

    let rpc_url: Url = env::var("RPC_URL")
        .context("RPC_URL must be set")?
        .parse()
        .context("Unable to parse RPC_URL")?;
    println!("RPC URL = {}", rpc_url);

    MultiChunkProverTester::setup()?;

    let client = ClientBuilder::default()
        .layer(RetryBackoffLayer::new(
            env::var("MAX_RATE_LIMIT_RETRIES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            env::var("RETRIES_INITIAL_BACKOFF")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
            u64::MAX,
        ))
        .layer(ThrottleLayer::new(
            env::var("REQUESTS_PER_SECOND")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
        ))
        .http(rpc_url);
    let provider = ProviderBuilder::<_, _, Network>::default()
        .with_recommended_fillers()
        .connect_client(client);

    let latest_block = provider
        .get_block_number()
        .await
        .context("Failed to get the latest block number")?;
    // fetch latest 100 blocks
    let n_chunks: u64 = env::var("N_CHUNKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let chunk_size: u64 = env::var("CHUNK_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    let start_block = latest_block
        .checked_sub(chunk_size * n_chunks)
        .context("Not enough blocks to fetch. Please decrease N_CHUNKS or CHUNK_SIZE.")?;
    println!(
        "blocks = {start_block}..={latest_block}; {chunk_size} blocks chunk, {n_chunks} chunks"
    );

    let witnesses = futures::future::try_join_all((start_block..=latest_block).map(|block| {
        let provider = provider.clone();
        async move {
            provider
                .dump_block_witness(block.into())
                .await
                .map(|w| w.unwrap())
        }
    }))
    .await?;

    let proving_tasks = witnesses
        .chunks_exact(chunk_size as usize)
        .map(|witnesses| ChunkProvingTask {
            block_witnesses: witnesses.to_vec(),
            prev_msg_queue_hash: Default::default(),
            fork_name: "euclidv2".to_string(),
        })
        .collect::<Vec<_>>();

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_rayon_threads().min(n_chunks as usize))
        .build()
        .unwrap();

    let (total_gas, total_cycle, total_tick) = pool.install(execute_multi(proving_tasks));

    println!(
        "Total gas: {}, Total cycles: {}, Average cycle/gas: {}, Average tick/gas: {}",
        total_gas,
        total_cycle,
        total_cycle as f64 / total_gas as f64,
        total_tick as f64 / total_gas as f64,
    );
    Ok(())
}
