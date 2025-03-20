use std::{
    fs::File,
    path::{Path, PathBuf},
};

use sbv_primitives::{B256, types::BlockWitness};
use scroll_zkvm_prover::{ChunkProverType, ProverType, task::chunk::ChunkProvingTask};

use crate::{ProverTester, testers::PATH_TESTDATA};

/// Load a file <block_n>.json in the <PATH_BLOCK_WITNESS> directory.
pub fn read_block_witness_from_testdata(block_n: usize) -> eyre::Result<BlockWitness> {
    let path_witness = Path::new(PATH_TESTDATA).join(format!("{}.json", block_n));
    read_block_witness(&path_witness)
}

/// Utility function to read and deserialize block witness given the block number.
pub fn read_block_witness<P>(path_witness: P) -> eyre::Result<BlockWitness>
where
    P: AsRef<Path>,
{
    let witness = File::open(path_witness)?;
    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
}

pub struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";

    /// [block-1, block-2, block-3, block-4]
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        let paths: Vec<PathBuf> = match std::env::var("TRACE_PATH") {
            Ok(paths) => glob::glob(&paths)?.filter_map(|entry| entry.ok()).collect(),
            Err(_) => {
                #[cfg(not(feature = "euclidv2"))]
                let blocks = 10319966usize..=10319974usize;
                #[cfg(feature = "euclidv2")]
                let blocks = 1usize..=4usize;
                blocks
                    .into_iter()
                    .map(|blk| Path::new(PATH_TESTDATA).join(format!("{}.json", blk)))
                    .collect()
            }
        };
        Ok(ChunkProvingTask {
            block_witnesses: paths
                .iter()
                .map(read_block_witness)
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
        let paths: Vec<Vec<PathBuf>> = match std::env::var("TRACE_PATH") {
            Ok(paths) => glob::glob(&paths)?
                .filter_map(|entry| entry.ok())
                .map(|p| vec![p])
                .collect(),
            Err(_) => {
                #[cfg(not(feature = "euclidv2"))]
                let blocks = vec![vec![12508460], vec![12508461], vec![12508462, 12508463]];
                #[cfg(feature = "euclidv2")]
                let blocks = vec![vec![1], vec![2], vec![3, 4]];
                blocks
                    .into_iter()
                    .map(|block_group| {
                        block_group
                            .into_iter()
                            .map(|block_n| {
                                Path::new(PATH_TESTDATA).join(format!("{}.json", block_n))
                            })
                            .collect()
                    })
                    .collect()
            }
        };

        let tasks = paths
            .into_iter()
            .map(|block_group| -> eyre::Result<_> {
                let block_witnesses = block_group
                    .iter()
                    .map(read_block_witness)
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?;
                Ok(ChunkProvingTask {
                    block_witnesses,
                    prev_msg_queue_hash: B256::repeat_byte(1u8),
                })
            })
            .collect::<eyre::Result<Vec<ChunkProvingTask>>>()?;
        Ok(tasks)
    }
}
