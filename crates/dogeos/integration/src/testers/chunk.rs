use crate::DOGEOS_TESTDATA_ROOT;
use bridge_adapters_zk::serde::SerdeWrapper;
use bridge_core::VerifierContext;
use sbv_primitives::B256;
use scroll_zkvm_integration::testers::chunk::read_block_witness;
use scroll_zkvm_integration::{ProverTester, tester_execute};
use scroll_zkvm_prover::utils::vm::ExecutionResult;
use scroll_zkvm_types::dogeos::chunk::{
    DogeOsChunkInfo, DogeOsChunkWitness, DogeOsChunkWitnessExtras,
};
use scroll_zkvm_types::public_inputs::{ForkName, Version};
use scroll_zkvm_types::scroll::chunk::ChunkWitness;
use std::fs::File;

pub struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Metadata = DogeOsChunkInfo;

    type Witness = DogeOsChunkWitness;

    const NAME: &str = "chunk";

    const PATH_PROJECT_ROOT: &str = "crates/dogeos/circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";
}

pub fn mock_chunk_witness() -> eyre::Result<DogeOsChunkWitness> {
    let block_witness_path = DOGEOS_TESTDATA_ROOT
        .join("mock")
        .join("witnesses")
        .join("1954897.json");
    let block_witness = read_block_witness(block_witness_path)?;

    let inner = ChunkWitness::new_scroll(
        Version::feynman().as_version_byte(),
        &[block_witness],
        B256::ZERO,
        ForkName::Feynman,
    );

    let header = serde_json::from_reader(File::open(
        DOGEOS_TESTDATA_ROOT
            .join("mock")
            .join("header_step_input.json"),
    )?)?;
    let midstate = serde_json::from_reader(File::open(
        DOGEOS_TESTDATA_ROOT
            .join("mock")
            .join("midstate_step_input.json"),
    )?)?;
    let extras = DogeOsChunkWitnessExtras {
        verifier_context: SerdeWrapper(VerifierContext::default()),
        header,
        midstate,
    };

    Ok(DogeOsChunkWitness { inner, extras })
}

pub fn exec_chunk(wit: &DogeOsChunkWitness) -> eyre::Result<(ExecutionResult, u64)> {
    let blk = wit.blocks[0].header.number;
    println!(
        "task block num: {}, block[0] idx: {}",
        wit.inner.blocks.len(),
        blk
    );
    let stats = wit.stats();
    println!("chunk stats {:#?}", stats);
    let exec_result = tester_execute::<ChunkProverTester>(wit, &[])?;
    let cycle_count = exec_result.total_cycle;
    let cycle_per_gas = cycle_count / stats.total_gas_used;
    println!(
        "blk {blk}->{}, cycle {cycle_count}, gas {}, cycle-per-gas {cycle_per_gas}",
        wit.blocks.last().unwrap().header.number,
        stats.total_gas_used,
    );
    eyre::Ok((exec_result, stats.total_gas_used))
}
