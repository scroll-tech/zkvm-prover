use alloy_primitives::B256;
use eyre::Ok;
use sbv_primitives::types::consensus::TxL1Message;
use scroll_zkvm_integration::testers::PATH_TESTDATA;
use scroll_zkvm_integration::testers::chunk::read_block_witness;
use scroll_zkvm_integration::testers::chunk::{exec_chunk, execute_multi};
use scroll_zkvm_integration::utils::get_rayon_threads;
use scroll_zkvm_integration::{
    ProverTester, prove_verify,
    testers::chunk::{
        ChunkProverTester, ChunkTaskGenerator, get_witness_from_env_or_builder, preset_chunk,
        preset_chunk_multiple,
    },
    utils::metadata_from_chunk_witnesses,
};
use scroll_zkvm_prover::utils::read_json;
use scroll_zkvm_types::public_inputs::Version;
use scroll_zkvm_types::scroll::chunk::{ChunkWitness, SecretKey};
use std::env;
use std::path::Path;

#[ignore = "can only run under eculidv2 hardfork"]
#[test]
fn test_cycle() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;

    // use rayon::prelude::*;

    let blocks = 1u64..=8u64;
    for blk in blocks {
        let mut task = ChunkTaskGenerator {
            block_range: (blk..=blk).collect(),
            ..Default::default()
        };

        let (exec_result, gas) = exec_chunk(&task.get_or_build_witness()?)?;
        let cycle_per_gas = exec_result.total_cycle / gas;
        assert!(cycle_per_gas < 30);
    }

    Ok(())
}

#[test]
fn test_execute() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let (exec_result, total_gas_used) = exec_chunk(&wit)?;
    let cycle_per_gas = exec_result.total_cycle / total_gas_used;
    assert_ne!(cycle_per_gas, 0);
    assert!(cycle_per_gas <= 35);
    Ok(())
}

#[test]
fn test_execute_validium() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;

    let base_dir = Path::new(PATH_TESTDATA).join("validium");

    let secret_key = hex::decode(env::var("VALIDIUM_KEY")?)?;
    let secret_key = SecretKey::try_from_bytes(&secret_key)?;

    for blk in [1019, 1256, 1276, 1141071] {
        let block_witness = read_block_witness(base_dir.join(format!("{blk}.json")))?;
        let validium_txs: Vec<TxL1Message> =
            read_json(base_dir.join(format!("{blk}_validium_txs.json")))?;

        let version = Version::validium_v1();
        let witness = ChunkWitness::new_validium(
            version.as_version_byte(),
            &[block_witness],
            B256::ZERO,
            version.fork,
            vec![validium_txs],
            secret_key.clone(),
        );

        exec_chunk(&witness)?;
    }
    Ok(())
}

#[ignore = "can only run under eculidv2 hardfork"]
#[test]
fn test_autofill_trie_nodes() -> eyre::Result<()> {
    use std::result::Result::Ok;
    ChunkProverTester::setup(true)?;

    let mut template_wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    template_wit.blocks.truncate(1);
    let wit = ChunkWitness::new_scroll(
        template_wit.version,
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
        let result = metadata_from_chunk_witnesses(test_wit);

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
    ChunkProverTester::setup(true)?;

    let tasks = preset_chunk_multiple()
        .into_iter()
        .map(|mut task| task.get_or_build_witness().unwrap())
        .collect::<Vec<_>>();

    // Execute tasks in parallel
    let (total_gas, total_cycle) = rayon::ThreadPoolBuilder::new()
        .num_threads(get_rayon_threads())
        .build()?
        .install(execute_multi(tasks));

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
    ChunkProverTester::setup(true)?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let (exec_result, _) = exec_chunk(&wit)?;
    let total_cycles = exec_result.total_cycle;

    println!(
        "scroll-zkvm-integration(chunk-circuit): total cycles = {:?}",
        total_cycles
    );

    Ok(())
}

#[test]
fn setup_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;
    let mut prover = ChunkProverTester::load_prover(false)?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let _ = prove_verify::<ChunkProverTester>(&mut prover, &wit, &[])?;

    Ok(())
}

#[test]
fn setup_axiom_prove_verify_single() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;
    let mut prover = ChunkProverTester::load_axiom_prover()?;

    let wit = get_witness_from_env_or_builder(&mut preset_chunk())?;
    let _ = prove_verify::<ChunkProverTester>(&mut prover, &wit, &[])?;

    Ok(())
}

#[test]
fn setup_prove_verify_multi() -> eyre::Result<()> {
    ChunkProverTester::setup(true)?;
    let mut prover = ChunkProverTester::load_prover(false)?;

    for mut task in preset_chunk_multiple() {
        let _ = task.get_or_build_proof(&mut prover)?;
    }

    Ok(())
}
