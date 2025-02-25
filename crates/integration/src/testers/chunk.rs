use std::{fs::File, path::Path};

use sbv::primitives::{B256, types::BlockWitness};
use scroll_zkvm_prover::{ChunkProverType, ProverType, task::chunk::ChunkProvingTask};

use crate::{ProverTester, testers::PATH_TESTDATA};

/// Load a file <block_n>.json in the <PATH_BLOCK_WITNESS> directory.
fn read_block_witness_from_testdata(block_n: usize) -> eyre::Result<BlockWitness> {
    read_block_witness(block_n, &Path::new(PATH_TESTDATA))
}

/// Utility function to read and deserialize block witness given the block number.
pub fn read_block_witness(block_n: usize, dir: &Path) -> eyre::Result<BlockWitness> {
    let path_witness = dir.join(format!("{}.json", block_n));
    let witness = File::open(&path_witness)?;
    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
}

pub struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";

    /// [block-1, block-2, block-3, block-4]
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        #[cfg(not(feature = "euclidv2"))]
        let blocks = 12508460usize..=12508463usize;
        #[cfg(feature = "euclidv2")]
        let blocks = 1usize..=4usize;
        Ok(ChunkProvingTask {
            block_witnesses: blocks
                .map(read_block_witness_from_testdata)
                .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            prev_msg_queue_hash: Default::default(),
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

    /// [block-1]
    /// [block-2]
    /// [block-3, block-4]
    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        #[cfg(not(feature = "euclidv2"))]
        let blocks = vec![vec![12508460], vec![12508461], vec![12508462, 12508463]];
        #[cfg(feature = "euclidv2")]
        let blocks = vec![vec![1], vec![2], vec![3, 4]];
        let msg_queue_hashes = std::iter::repeat(B256::repeat_byte(1u8));
        let tasks = blocks
            .into_iter()
            .zip(msg_queue_hashes)
            .map(|(block_group, prev_msg_queue_hash)| -> eyre::Result<_> {
                let block_witnesses = block_group
                    .iter()
                    .copied()
                    .map(read_block_witness_from_testdata)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?;
                Ok(ChunkProvingTask {
                    block_witnesses,
                    prev_msg_queue_hash,
                })
            })
            .collect::<eyre::Result<Vec<ChunkProvingTask>>>()?;
        Ok(tasks)
    }
}
