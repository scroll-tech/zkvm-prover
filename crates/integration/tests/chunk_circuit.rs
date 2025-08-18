use std::env;
use std::path::Path;
use alloy_primitives::B256;
use eyre::Ok;
use scroll_zkvm_integration::{
    ProverTester, prove_verify, tester_execute,
    testers::chunk::{
        ChunkProverTester, ChunkTaskGenerator, get_witness_from_env_or_builder, preset_chunk,
        preset_chunk_multiple,
    },
    utils::metadata_from_chunk_witnesses,
};
use scroll_zkvm_integration::testers::chunk::read_block_witness;
use scroll_zkvm_integration::testers::PATH_TESTDATA;
use scroll_zkvm_prover::{Prover, utils::vm::ExecutionResult};
use scroll_zkvm_prover::utils::read_json;
use scroll_zkvm_types::chunk::ChunkWitness;
use scroll_zkvm_types::public_inputs::chunk::validium::{QueueTransaction, SecretKey};
use scroll_zkvm_types::public_inputs::ForkName;

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

#[test]
fn test_validium_execute() -> eyre::Result<()> {
    ChunkProverTester::setup()?;
    let prover = ChunkProverTester::load_prover(false)?;

    let base_dir = Path::new(PATH_TESTDATA).join("validium");

    let secret_key = hex::decode(env::var("VALIDIUM_KEY")?)?;
    let secret_key = SecretKey::try_from_bytes(&secret_key)?;

    for blk in [1019, 1256, 1276] {
        let block_witness = read_block_witness(base_dir.join(format!("{blk}.json")))?;
        let validium_txs: Vec<QueueTransaction> = read_json(base_dir.join(format!("{blk}_validium_txs.json")))?;

        let witness = ChunkWitness::new_validium(
            &[block_witness],
            B256::ZERO,
            ForkName::EuclidV2,
            vec![validium_txs],
            secret_key.clone(),
        );

        exec_chunk(&prover, &witness)?;
    }
    Ok(())
}

#[ignore = "can only run under eculidv2 hardfork"]
#[test]
fn test_autofill_trie_nodes() -> eyre::Result<()> {
    use std::result::Result::Ok;
    ChunkProverTester::setup()?;

    let mut template_wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    template_wit.blocks.truncate(1);
    let wit = ChunkWitness::new_scroll(
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

#[test]
fn test_execute_multi() -> eyre::Result<()> {
    // use rayon::iter::{IntoParallelIterator, ParallelIterator};

    ChunkProverTester::setup()?;

    // Initialize Rayon thread pool with 8 threads
    let parallel = 8;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(parallel)
        .build()
        .unwrap();
    // Execute tasks in parallel
    let (total_gas, total_cycle) = pool.install(|| {
        // comment by fan@scroll.io: why we need to load prover multiple times (which is time costing)
        let prover = ChunkProverTester::load_prover(false).unwrap();
        let init = (0u64, 0u64);
        let adder =
            |(gas1, cycle1): (u64, u64), (gas2, cycle2): (u64, u64)| (gas1 + gas2, cycle1 + cycle2);
        preset_chunk_multiple()
            .into_iter()
            .map(|mut task| -> (u64, u64) {
                let (exec_result, gas) =
                    exec_chunk(&prover, &task.get_or_build_witness().unwrap()).unwrap();
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
