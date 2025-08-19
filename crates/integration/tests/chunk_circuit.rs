use std::fs::File;
use std::path::PathBuf;
use alloy_primitives::B256;
use eyre::{Context, ContextCompat, Ok};
use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use sbv_primitives::BlockWitness;
use scroll_zkvm_integration::utils::get_rayon_threads;
use scroll_zkvm_integration::{
    ProverTester, prove_verify, tester_execute,
    testers::chunk::{
        ChunkProverTester, ChunkTaskGenerator, get_witness_from_env_or_builder, preset_chunk,
        preset_chunk_multiple,
    },
    utils::metadata_from_chunk_witnesses,
};
use scroll_zkvm_prover::{Prover, utils::vm::ExecutionResult};
use scroll_zkvm_types::chunk::ChunkWitness;
use scroll_zkvm_types::public_inputs::ForkName;

thread_local! {
    static PROVER: Prover = ChunkProverTester::load_prover(false).unwrap();
}

fn exec_chunk(prover: &Prover, wit: &ChunkWitness) -> eyre::Result<(ExecutionResult, u64)> {
    let blk = wit.blocks[0].header.number;
    println!(
        "task block num: {}, block[0] idx: {}",
        wit.blocks.len(),
        blk
    );
    let stats = wit.stats();
    println!("chunk stats {:#?}", stats);
    let exec_result = tester_execute::<ChunkProverTester>(prover, wit, &[])?;
    let cycle_count = exec_result.total_cycle as u64;
    let cycle_per_gas = cycle_count / stats.total_gas_used;
    println!(
        "blk {blk}->{}, cycle {cycle_count}, gas {}, cycle-per-gas {cycle_per_gas}",
        wit.blocks.last().unwrap().header.number,
        stats.total_gas_used,
    );
    Ok((exec_result, stats.total_gas_used))
}

#[ignore = "can only run under eculidv2 hardfork"]
#[test]
fn test_cycle() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    // use rayon::prelude::*;
    let prover = ChunkProverTester::load_prover(false)?;

    let blocks = 1u64..=8u64;
    for blk in blocks {
        let mut task = ChunkTaskGenerator {
            block_range: (blk..=blk).collect(),
            ..Default::default()
        };

        let (exec_result, gas) = exec_chunk(&prover, &task.get_or_build_witness()?)?;
        let cycle_per_gas = exec_result.total_cycle / gas;
        assert!(cycle_per_gas < 30);
    }

    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup()?;
    let prover = ChunkProverTester::load_prover(false)?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let (exec_result, total_gas_used) = exec_chunk(&prover, &wit)?;
    let cycle_per_gas = exec_result.total_cycle / total_gas_used;
    assert_ne!(cycle_per_gas, 0);
    assert!(cycle_per_gas <= 35);
    Ok(())
}

#[ignore = "can only run under eculidv2 hardfork"]
#[test]
fn test_autofill_trie_nodes() -> eyre::Result<()> {
    use std::result::Result::Ok;
    ChunkProverTester::setup()?;

    let mut template_wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    template_wit.blocks.truncate(1);
    let wit = ChunkWitness::new(
        &template_wit.blocks,
        template_wit.prev_msg_queue_hash,
        template_wit.fork_name,
    );
    for index in [10, 13] {
        println!(
            "removing state at index {}: {:?}",
            index, wit.blocks[0].states[index]
        );
        let mut test_wit = wit.clone();
        test_wit.blocks[0].states.remove(index);
        let result = metadata_from_chunk_witnesses(&test_wit);

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

fn execute_multi(wits: Vec<ChunkWitness>) -> impl FnOnce() -> (u64, u64) + Send + Sync + 'static {
    || {
        wits.into_par_iter()
            .map(|wit| -> (u64, u64) {
                let (exec_result, gas) = PROVER.with(|prover| exec_chunk(&prover, &wit).unwrap());
                (gas, exec_result.total_cycle)
            })
            .reduce(
                || (0u64, 0u64),
                |(gas1, cycle1): (u64, u64), (gas2, cycle2): (u64, u64)| {
                    (gas1 + gas2, cycle1 + cycle2)
                },
            )
    }
}

#[test]
fn test_execute_multi() -> eyre::Result<()> {
    ChunkProverTester::setup()?;

    // Initialize Rayon thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_rayon_threads())
        .build()?;

    // Execute tasks in parallel
    let tasks = preset_chunk_multiple()
        .into_iter()
        .map(|mut task| task.get_or_build_witness().unwrap())
        .collect::<Vec<_>>();
    let (total_gas, total_cycle) = pool.install(execute_multi(tasks));

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
    let prover = ChunkProverTester::load_prover(false)?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let (exec_result, _) = exec_chunk(&prover, &wit)?;
    let total_cycles = exec_result.total_cycle;

    println!(
        "scroll-zkvm-integration(chunk-circuit): total cycles = {:?}",
        total_cycles
    );

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup()?;
    let mut prover = ChunkProverTester::load_prover(false)?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let _ = prove_verify::<ChunkProverTester>(&mut prover, &wit, &[])?;

    Ok(())
}

#[test]
fn setup_prove_verify_multi() -> eyre::Result<()> {
    ChunkProverTester::setup()?;
    let mut prover = ChunkProverTester::load_prover(false)?;

    for mut task in preset_chunk_multiple() {
        let _ = task.get_or_build_proof(&mut prover)?;
    }

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

    let out_path = env::var("OUT_PATH")
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|_| PathBuf::from("scanner.csv"));
    println!("out_path = {}", out_path.display());
    let out = File::create(&out_path)?;
    let mut writer = csv::Writer::from_writer(out);

    ChunkProverTester::setup()?;

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

    // fetch latest 1000 blocks
    let n_chunks: u64 = env::var("N_CHUNKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50);
    let chunk_size: u64 = env::var("CHUNK_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);
    let start_block = latest_block
        .checked_sub(chunk_size * n_chunks)
        .context("Not enough blocks to fetch. Please decrease N_CHUNKS or CHUNK_SIZE.")?;
    println!(
        "blocks = {start_block}..={latest_block}; {chunk_size} blocks chunk, {n_chunks} chunks"
    );

    let blocks = futures::future::try_join_all((start_block..=latest_block).map(|block| {
        let provider = provider.clone();
        async move {
            provider
                .dump_block_witness(block.into())
                .await
                .map(|w| w.unwrap())
        }
    }))
    .await?;

    // Initialize Rayon thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_rayon_threads())
        .build()?;

    #[derive(serde::Serialize)]
    struct Stats {
        start_block: u64,
        end_block: u64,
        tx_num: usize,
        cycle: u64,
        gas: u64,
        cycle_per_gas: f64,
    }

    let stats = pool.install(move || {
        blocks
            .chunks_exact(chunk_size as usize)
            .par_bridge()
            .map(|blocks| {
                let wit = ChunkWitness::new(blocks, B256::ZERO, ForkName::Feynman);
                let (exec_result, gas) = PROVER.with(|prover| exec_chunk(&prover, &wit).unwrap());
                // Block range, tx num, cycle, gas, cycle-per_gas
                let stats = Stats {
                    start_block: blocks[0].header.number,
                    end_block: blocks.last().unwrap().header.number,
                    tx_num: blocks.iter().map( | b| b.num_transactions()).sum::<usize>(),
                    cycle: exec_result.total_cycle,
                    gas,
                    cycle_per_gas: exec_result.total_cycle as f64 / gas as f64,
                };
                println!(
                    "Blocks {}..={} | Tx: {} | Cycle: {} | Gas: {} | Cycle/Gas: {:.2}",
                    stats.start_block,
                    stats.end_block,
                    stats.tx_num,
                    stats.cycle,
                    stats.gas,
                    stats.cycle_per_gas
                );
                stats
            })
            .collect::<Vec<Stats>>()
    });

    for stat in stats {
        writer.serialize(stat).context("Failed to write stats to CSV")?;
    }
    writer.flush().context("Failed to flush CSV")?;

    Ok(())
}
