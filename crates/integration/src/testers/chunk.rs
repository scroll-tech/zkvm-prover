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
                block_witnesses: vec![read_block_witness_str("0x2.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0x3.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0x4.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0x5.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0x6.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("0x7.json")?,
                    read_block_witness_str("0x8.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0x9.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0xA.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0xB.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![read_block_witness_str("0xC.json")?],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("0xD.json")?,
                    read_block_witness_str("0xE.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("0xF.json")?,
                    read_block_witness_str("0x10.json")?,
                    read_block_witness_str("0x11.json")?,
                    read_block_witness_str("0x12.json")?,
                    read_block_witness_str("0x13.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("0x14.json")?,
                    read_block_witness_str("0x15.json")?,
                    read_block_witness_str("0x16.json")?,
                    read_block_witness_str("0x17.json")?,
                    read_block_witness_str("0x18.json")?,
                ],
            },
            ChunkProvingTask {
                block_witnesses: vec![
                    read_block_witness_str("0x19.json")?,
                    read_block_witness_str("0x1A.json")?,
                    read_block_witness_str("0x1B.json")?,
                    read_block_witness_str("0x1C.json")?,
                    read_block_witness_str("0x1D.json")?,
                ],
            },
        ])
    }
}
