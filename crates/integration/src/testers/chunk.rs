use std::{
    fs::File,
    path::{Path, PathBuf},
};

use sbv_primitives::{B256, BlockWitness};
use scroll_zkvm_prover::{ChunkProverType, ProverType, task::chunk::ChunkProvingTask};
use scroll_zkvm_types::public_inputs::ForkName;

use crate::{
    ProverTester,
    testers::PATH_TESTDATA,
    utils::{testdata_fork_directory, testing_hardfork},
};

/// Load a file <block_n>.json in the <PATH_BLOCK_WITNESS> directory.
pub fn read_block_witness_from_testdata(block_n: usize) -> eyre::Result<BlockWitness> {
    read_block_witness(
        Path::new(PATH_TESTDATA)
            .join(testdata_fork_directory())
            .join("witnesses")
            .join(format!("{}.json", block_n)),
    )
}

/// Utility function to read and deserialize block witness given the block number.
pub fn read_block_witness<P>(path_witness: P) -> eyre::Result<BlockWitness>
where
    P: AsRef<Path>,
{
    if !path_witness.as_ref().exists() {
        println!("File not found: {:?}", path_witness.as_ref());
        return Err(eyre::eyre!("File not found: {:?}", path_witness.as_ref()));
    }
    let content = std::fs::read(path_witness)?;
    let result = BlockWitness::from_json_slice(&content)?;
    Ok(result)
}

pub struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProverType;

    const PATH_PROJECT_ROOT: &str = "crates/circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";

    /// [block-1, block-2, block-3, block-4]
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        let paths: Vec<PathBuf> = match std::env::var("TRACE_PATH") {
            Ok(paths) => {
                let paths: Vec<_> = glob::glob(&paths)?.filter_map(|entry| entry.ok()).collect();
                if paths.is_empty() {
                    return Err(eyre::eyre!("No files found in the given path"));
                }
                paths
            }
            Err(_) => {
                let blocks = match testing_hardfork() {
                    ForkName::EuclidV1 => 12508460usize..=12508463usize,
                    ForkName::EuclidV2 => 1usize..=4usize,
                    ForkName::Feynman => 16525000usize..=16525019usize,
                };
                blocks
                    .into_iter()
                    .map(|block_n| {
                        Path::new(PATH_TESTDATA)
                            .join(testdata_fork_directory())
                            .join("witnesses")
                            .join(format!("{}.json", block_n))
                    })
                    .collect()
            }
        };

        Ok(ChunkProvingTask {
            block_witnesses: paths
                .iter()
                .map(read_block_witness)
                .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            prev_msg_queue_hash: B256::repeat_byte(1u8),
            fork_name: testing_hardfork().to_string(),
        })
    }
}

/// helper func to gen a series of proving tasks, specified by the block number
pub fn gen_multi_tasks(
    blocks: impl IntoIterator<Item = Vec<i32>>,
) -> eyre::Result<Vec<<ChunkProverType as ProverType>::ProvingTask>> {
    let paths: Vec<Vec<PathBuf>> = match std::env::var("TRACE_PATH") {
        Ok(paths) => glob::glob(&paths)?
            .filter_map(|entry| entry.ok())
            .map(|p| vec![p])
            .collect(),
        Err(_) => blocks
            .into_iter()
            .map(|block_group| {
                block_group
                    .into_iter()
                    .map(|block_n| {
                        Path::new(PATH_TESTDATA)
                            .join(testdata_fork_directory())
                            .join("witnesses")
                            .join(format!("{}.json", block_n))
                    })
                    .collect()
            })
            .collect(),
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
                fork_name: testing_hardfork().to_string(),
            })
        })
        .collect::<eyre::Result<Vec<ChunkProvingTask>>>()?;

    Ok(tasks)
}

pub struct MultiChunkProverTester;

impl ProverTester for MultiChunkProverTester {
    type Prover = ChunkProverType;

    const PATH_PROJECT_ROOT: &str = "crates/circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        unreachable!("Use gen_multi_proving_tasks");
    }

    /// [block-1]
    /// [block-2]
    /// [block-3, block-4]
    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        let blocks = match testing_hardfork() {
            ForkName::EuclidV1 => [vec![12508460], vec![12508461], vec![12508462, 12508463]],
            ForkName::EuclidV2 => [vec![1], vec![2], vec![3, 4]],
            ForkName::Feynman => [vec![16525000], vec![16525001], vec![16525002, 16525003]],
        };
        gen_multi_tasks(blocks)
    }
}
