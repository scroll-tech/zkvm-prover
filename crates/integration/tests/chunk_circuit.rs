use std::{fs::File, path::Path};

use sbv::primitives::types::BlockWitness;
use scroll_zkvm_integration::{ProverTester, prove_verify_common};
use scroll_zkvm_prover::{ChunkProver, ProverVerifier, task::chunk::ChunkProvingTask};

const PATH_BLOCK_WITNESS: &str = "./testdata";

struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const PREFIX: &str = "chunk";

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

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    prove_verify_common::<ChunkProverTester>()
}
