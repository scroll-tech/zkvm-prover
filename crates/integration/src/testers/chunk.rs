use std::{fs::File, path::Path};

use sbv::primitives::types::BlockWitness;
use scroll_zkvm_prover::{ChunkProverType, ProverType, task::chunk::ChunkProvingTask};

use crate::{ProverTester, testers::PATH_TESTDATA};

/// Utility function to read and deserialize block witness given the block number.
///
/// Expects a file <block_n>.json to be present in the <PATH_BLOCK_WITNESS> directory.
fn read_block_witness(block_n: usize) -> eyre::Result<BlockWitness> {
    let path_witness = Path::new(PATH_TESTDATA).join(format!("{}.json", block_n));
    let witness = File::open(&path_witness)?;
    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
}

fn read_block_witness_str(block_n: &str) -> eyre::Result<BlockWitness> {
    let path_witness = Path::new(PATH_TESTDATA).join("witnesses").join(block_n);
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
            block_witnesses: (12508460usize..=12508463)
                .map(read_block_witness)
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
                block_witnesses: vec![read_block_witness_str("2.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("3.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("4.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("5.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("6.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("7.json")?,
                    read_block_witness_str("8.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("9.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("10.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("11.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("12.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("13.json")?,
                    read_block_witness_str("14.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("15.json")?,
                    read_block_witness_str("16.json")?,
                    read_block_witness_str("17.json")?,
                    read_block_witness_str("18.json")?,
                    read_block_witness_str("19.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("20.json")?,
                    read_block_witness_str("21.json")?,
                    read_block_witness_str("22.json")?,
                    read_block_witness_str("23.json")?,
                    read_block_witness_str("24.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("25.json")?,
                    read_block_witness_str("26.json")?,
                    read_block_witness_str("27.json")?,
                    read_block_witness_str("28.json")?,
                    read_block_witness_str("29.json")?,
                ],
            },
        ])
    }
}
