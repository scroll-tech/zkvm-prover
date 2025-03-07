use std::{fs::File, path::Path};

use sbv::primitives::types::BlockWitness;
use scroll_zkvm_prover::{ChunkProverType, ProverType, task::chunk::ChunkProvingTask};

use crate::{ProverTester, testers::PATH_TESTDATA};

/// Utility function to read and deserialize block witness given the block number.
///
/// Expects a file <block_n>.json to be present in the <PATH_BLOCK_WITNESS> directory.
#[allow(dead_code)]
fn read_block_witness(block_n: usize) -> eyre::Result<BlockWitness> {
    let path_witness = Path::new(PATH_TESTDATA).join(format!("{}.json", block_n));
    let witness = File::open(&path_witness)?;
    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
}

/// Utility function to read and deserialize block witness given the block number.
///
/// Expects a file <block_n>.json to be present in the <PATH_BLOCK_WITNESS> directory.
fn read_block_witness_failed(block_n: usize) -> eyre::Result<BlockWitness> {
    let path_witness = Path::new(PATH_TESTDATA)
        .join("failed-witnesses")
        .join(format!("{}.json", block_n));
    let witness = File::open(&path_witness)?;
    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
}

pub struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";

    /// [block-12508460, block-12508461, block-12508462, block-12508463]
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        Ok(ChunkProvingTask {
            block_witnesses: (581..=590)
                .map(read_block_witness_failed)
                .collect::<eyre::Result<Vec<BlockWitness>>>()?,
        })
    }
}

pub struct MultiChunkProverTester;

impl ProverTester for MultiChunkProverTester {
    type Prover = ChunkProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        unreachable!("Use gen_multi_proving_tasks");
    }

    /// [block-12508460]
    /// [block-12508461]
    /// [block-12508462, block-12508463]
    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        Ok(vec![
            ChunkProvingTask {
                block_witnesses: (197..=293)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (294..=386)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (387..=470)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (471..=480)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (481..=490)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (491..=500)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (501..=510)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (511..=520)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (521..=530)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (531..=540)
                    .map(read_block_witness_failed)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
        ])
    }
}
