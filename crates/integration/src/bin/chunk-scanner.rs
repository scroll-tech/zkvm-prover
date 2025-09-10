use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_transport::layers::{RetryBackoffLayer, ThrottleLayer};
use clap::Parser;
use eyre::{Context, ContextCompat};
use sbv_core::BlockWitness;
use sbv_primitives::{B256, types::Network};
use sbv_utils::rpc::ProviderExt;
use scroll_zkvm_integration::{
    ProverTester,
    testers::chunk::{ChunkProverTester, exec_chunk},
};
use scroll_zkvm_types::{chunk::ChunkWitness, public_inputs::ForkName};
use std::collections::HashMap;
use std::{fs::File, path::PathBuf, slice};
use url::Url;

#[derive(Parser)]
struct Cli {
    #[arg(long, env = "RPC_URL", help = "The RPC URL to connect to")]
    rpc_url: Url,
    #[arg(
        long,
        env = "OUT_PATH",
        default_value = "scanner.csv",
        help = "The output CSV file path"
    )]
    out_path: PathBuf,

    #[arg(
        long,
        env = "CHUNK_GAS_TARGET",
        default_value_t = 24,
        help = "Target gas per chunk (in millions of gas)"
    )]
    chunk_gas_target: u64,
    #[arg(
        long,
        env = "N_CHUNKS",
        default_value_t = 50,
        help = "Number of chunks to process"
    )]
    n_chunks: u64,

    #[arg(
        long,
        env = "BLOCK_GAS_ESTIMATED",
        default_value_t = 1,
        help = "Block gas estimated (in millions of gas), used when start_block is not set"
    )]
    block_gas_estimated: u64,
    #[arg(
        long,
        env = "START_BLOCK",
        help = "The start block number (inclusive). If not set, use latest - N_CHUNKS * (CHUNK_GAS_TARGET / BLOCK_GAS_ESTIMATED)"
    )]
    start_block: Option<u64>,

    #[arg(
        long,
        env = "COMPARE_WITH",
        help = "Compare the results with an existing CSV file"
    )]
    compare_with: Option<PathBuf>,

    #[arg(
        long,
        env = "REQUESTS_PER_SECOND",
        default_value_t = 10,
        help = "Max requests per second"
    )]
    requests_per_second: u32,
    #[arg(
        long,
        env = "MAX_RATE_LIMIT_RETRIES",
        default_value_t = 10,
        help = "Max retries on rate limit"
    )]
    max_rate_limit_retries: u32,
    #[arg(
        long,
        env = "RETRIES_INITIAL_BACKOFF",
        default_value_t = 100,
        help = "Initial backoff in ms for retries"
    )]
    retries_initial_backoff: u64,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Stats {
    start_block: u64,
    end_block: u64,
    tx_num: usize,
    cycle: u64,
    gas: u64,
    cycle_per_gas: f64,
    diff_percentage: Option<f64>,
    diff_absolute: Option<i64>,
}

#[tokio::main]
async fn main() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;

    let cli = Cli::parse();

    println!("RPC URL = {}", cli.rpc_url);
    println!("out_path = {}", cli.out_path.display());
    let client = ClientBuilder::default()
        .layer(RetryBackoffLayer::new(
            cli.max_rate_limit_retries,
            cli.retries_initial_backoff,
            u64::MAX,
        ))
        .layer(ThrottleLayer::new(cli.requests_per_second))
        .http(cli.rpc_url);
    let provider = ProviderBuilder::<_, _, Network>::default()
        .with_recommended_fillers()
        .connect_client(client);

    let compare_with: Option<HashMap<(u64, u64), Stats>> = cli.compare_with.map(|compare_with| {
        csv::Reader::from_path(compare_with)?
            .into_deserialize::<Stats>()
            .map(|r| r.map(|stats| ((stats.start_block, stats.end_block), stats)))
            .collect::<Result<_, _>>()
    }).transpose()?;

    let out = File::create(&cli.out_path)?;
    let mut writer = csv::Writer::from_writer(out);

    let start_block = if let Some(b) = cli.start_block {
        b
    } else {
        let latest_block = provider
            .get_block_number()
            .await
            .context("Failed to fetch latest block number")?;
        let estimated_blocks_required = cli.chunk_gas_target / cli.block_gas_estimated;
        latest_block
            .checked_sub(estimated_blocks_required)
            .context("estimated start block overflowed; please adjust args")?
    };

    println!(
        "scan blocks from {start_block}; {chunk_gas_target}M Gas chunk, {n_chunks} chunks",
        chunk_gas_target = cli.chunk_gas_target,
        n_chunks = cli.n_chunks,
    );

    let (tx, mut rx) = tokio::sync::mpsc::channel(100);
    tokio::spawn(fetcher(tx, provider.clone(), start_block));

    let mut blocks = vec![];
    let mut gas_used = 0u64;
    while let Some(block) = rx.recv().await {
        let (_, gas) = exec_chunk(&ChunkWitness::new(
            slice::from_ref(&block),
            B256::ZERO,
            ForkName::Feynman,
        ))?;

        if gas + gas_used > cli.chunk_gas_target * 1_000_000 {
            let wit = ChunkWitness::new(&blocks, B256::ZERO, ForkName::Feynman);
            let (exec_result, gas) = exec_chunk(&wit)?;

            let start_block = blocks[0].header.number;
            let end_block = blocks.last().unwrap().header.number;
            let cycle = exec_result.total_cycle;

            let old_cycle = compare_with
                .as_ref()
                .and_then(|m| m.get(&(start_block, end_block)))
                .map(|old_stats| old_stats.cycle);
            let diff_absolute = old_cycle.map(|old| cycle as i64 - old as i64);
            let diff_percentage = old_cycle.zip(diff_absolute).map(|(old, diff)| (diff as f64) / (old as f64) * 100.0);

            let stats = Stats {
                start_block,
                end_block,
                tx_num: blocks.iter().map(|b| b.transactions.len()).sum::<usize>(),
                cycle,
                gas,
                cycle_per_gas: exec_result.total_cycle as f64 / gas as f64,
                diff_percentage,
                diff_absolute,
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
            writer
                .serialize(stats)
                .context("Failed to write stats to CSV")?;
            writer.flush().context("Failed to flush CSV")?;
            blocks = vec![block];
            gas_used = gas;
        } else {
            blocks.push(block);
            gas_used += gas;
        }
    }

    Ok(())
}

async fn fetcher(
    tx: tokio::sync::mpsc::Sender<BlockWitness>,
    provider: impl Provider<Network> + Clone,
    start_block: u64,
) -> eyre::Result<()> {
    let mut block_number = start_block;
    let prev_state_root: Option<B256> = None;
    loop {
        let req = provider.dump_block_witness(block_number);
        let req = if let Some(prev_state_root) = prev_state_root {
            req.with_prev_state_root(prev_state_root)
        } else {
            req
        };
        let Some(block) = req.send().await.transpose() else {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await; // wait for new block
            continue;
        };
        let block = block?;
        tx.send(block).await?;
        block_number += 1;
    }
}
