//! Chunk witness building for the ZisK benchmark host.
//!
//! Trimmed subset of `sp1/prover-test/src/witness.rs` — only the chunk path is needed
//! for the ZisK chunk PoC benchmark. Reads the same shared GalileoV2 testdata the
//! OpenVM and SP1 integration tests use, so the ZisK chunk execution is measured on an
//! identical Scroll workload.

use std::path::{Path, PathBuf};

use eyre::Context;
use sbv_core::witness::BlockWitness;
use sbv_primitives::B256;
use scroll_zkvm_types_base::public_inputs::Version;
use scroll_zkvm_types_chunk::scroll::ChunkWitness;

const PATH_TESTDATA: &str = "../crates/integration/testdata";

/// Default fork/version used by the OpenVM + SP1 integration tests.
pub fn testing_version() -> Version {
    Version::galileo_v2()
}

/// Read a block witness JSON file from the shared testdata.
pub fn read_block_witness<P>(path: P) -> eyre::Result<BlockWitness>
where
    P: AsRef<Path>,
{
    let path = path.as_ref();
    if !path.exists() {
        eyre::bail!("block witness file not found: {}", path.display());
    }

    if let Ok(ret) = serde_json::from_reader::<_, BlockWitness>(std::fs::File::open(path)?) {
        Ok(ret)
    } else {
        let witness = std::fs::File::open(path)?;
        Ok(BlockWitness::from(serde_json::from_reader::<
            _,
            sbv_primitives::legacy_types::BlockWitness,
        >(witness)?))
    }
}

/// Build a `ChunkWitness` from a contiguous block range using shared testdata.
pub fn build_chunk_witness(block_range: impl Iterator<Item = u64>) -> eyre::Result<ChunkWitness> {
    let version = testing_version();
    let fork_dir = version.fork.to_string();
    let paths: Vec<PathBuf> = block_range
        .map(|block_n| {
            Path::new(PATH_TESTDATA)
                .join(&fork_dir)
                .join("witnesses")
                .join(format!("{}.json", block_n))
        })
        .collect();

    let block_witnesses: Vec<BlockWitness> = paths
        .iter()
        .map(read_block_witness)
        .collect::<eyre::Result<Vec<_>>>()
        .context("failed to read block witnesses")?;

    Ok(ChunkWitness::new_scroll(
        version.as_version_byte(),
        &block_witnesses,
        B256::repeat_byte(1u8),
        version.fork,
    ))
}

/// Default single-chunk block range matching OpenVM/SP1 `preset_chunk`.
pub fn preset_chunk_block_range() -> Vec<u64> {
    (20239240u64..=20239245).collect()
}
