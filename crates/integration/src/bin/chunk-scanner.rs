use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_transport::layers::{RetryBackoffLayer, ThrottleLayer};
use clap::Parser;
use eyre::Context;
use eyre::ContextCompat;
use rayon::iter::ParallelBridge;
use rayon::iter::ParallelIterator;
use sbv_primitives::{B256, types::Network};
use sbv_utils::rpc::ProviderExt;
use scroll_zkvm_integration::ProverTester;
use scroll_zkvm_integration::testers::chunk::{ChunkProverTester, exec_chunk};
use scroll_zkvm_integration::utils::get_rayon_threads;
use scroll_zkvm_types::chunk::ChunkWitness;
use scroll_zkvm_types::public_inputs::ForkName;
use std::fs::File;
use std::path::PathBuf;
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
        env = "N_CHUNKS",
        default_value_t = 50,
        help = "Number of chunks to process"
    )]
    n_chunks: u64,
    #[arg(
        long,
        env = "CHUNK_SIZE",
        default_value_t = 20,
        help = "Number of blocks per chunk"
    )]
    chunk_size: u64,

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

#[derive(serde::Serialize)]
struct Stats {
    start_block: u64,
    end_block: u64,
    tx_num: usize,
    cycle: u64,
    gas: u64,
    cycle_per_gas: f64,
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

    let out = File::create(&cli.out_path)?;
    let mut writer = csv::Writer::from_writer(out);

    let latest_block = provider
        .get_block_number()
        .await
        .context("Failed to get the latest block number")?;

    // fetch latest 1000 blocks
    let start_block = latest_block
        .checked_sub(cli.chunk_size * cli.n_chunks)
        .context("Not enough blocks to fetch. Please decrease N_CHUNKS or CHUNK_SIZE.")?;
    println!(
        "blocks = {start_block}..={latest_block}; {chunk_size} blocks chunk, {n_chunks} chunks",
        chunk_size = cli.chunk_size,
        n_chunks = cli.n_chunks,
    );

    let blocks = futures::future::try_join_all((start_block..=latest_block).map(|block| {
        let provider = provider.clone();
        async move {
            provider
                .dump_block_witness(block)
                .send()
                .await
                .map(|w| w.unwrap())
        }
    }))
    .await?;

    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(get_rayon_threads())
        .build()?;

    let stats = pool.install(move || {
        blocks
            .chunks_exact(cli.chunk_size as usize)
            .par_bridge()
            .map(|blocks| {
                let wit = ChunkWitness::new(blocks, B256::ZERO, ForkName::Feynman);
                let (exec_result, gas) = exec_chunk(&wit).unwrap();
                // Block range, tx num, cycle, gas, cycle-per_gas
                let stats = Stats {
                    start_block: blocks[0].header.number,
                    end_block: blocks.last().unwrap().header.number,
                    tx_num: blocks.iter().map(|b| b.transactions.len()).sum::<usize>(),
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
        writer
            .serialize(stat)
            .context("Failed to write stats to CSV")?;
    }
    writer.flush().context("Failed to flush CSV")?;

    Ok(())
}
