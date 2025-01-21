use std::{fs::File, path::Path};

use sbv::primitives::types::BlockWitness;
use scroll_zkvm_prover::{ChunkProver, ProverVerifier, task::chunk::ChunkProvingTask};

use crate::ProverTester;

const PATH_BLOCK_WITNESS: &str = "./testdata";

pub struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const PREFIX: &str = "chunk";

    /// [block-12508460, block-12508461, block-12508462, block-12508463]
    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        Ok(ChunkProvingTask {
            block_witnesses: (12508460usize..=12508463)
                .map(|block_n| {
                    let witness =
                        File::open(Path::new(PATH_BLOCK_WITNESS).join(block_n.to_string()))?;
                    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
                })
                .collect::<eyre::Result<Vec<BlockWitness>>>()?,
        })
    }
}

pub struct MultiChunkProverTester;

impl ProverTester for MultiChunkProverTester {
    type Prover = ChunkProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const PREFIX: &str = "chunk";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        unimplemented!()
    }

    /// [block-12508460]
    /// [block-12508461]
    /// [block-12508462, block-12508463]
    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverVerifier>::ProvingTask>>
    {
        Ok(vec![
            ChunkProvingTask {
                block_witnesses: (12508460usize..=12508460)
                    .map(|block_n| {
                        let witness =
                            File::open(Path::new(PATH_BLOCK_WITNESS).join(block_n.to_string()))?;
                        Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
                    })
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (12508461usize..=12508461)
                    .map(|block_n| {
                        let witness =
                            File::open(Path::new(PATH_BLOCK_WITNESS).join(block_n.to_string()))?;
                        Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
                    })
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
            ChunkProvingTask {
                block_witnesses: (12508462usize..=12508463)
                    .map(|block_n| {
                        let witness =
                            File::open(Path::new(PATH_BLOCK_WITNESS).join(block_n.to_string()))?;
                        Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
                    })
                    .collect::<eyre::Result<Vec<BlockWitness>>>()?,
            },
        ])
    }
}
