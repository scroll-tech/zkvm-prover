use scroll_zkvm_prover::{BatchProver, ProverVerifier};

use crate::ProverTester;

pub struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Prover = BatchProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const ASSETS_DIR: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        todo!("BatchProverTester: gen_proving_task not implemented")
    }
}

pub struct MultiBatchProverTester;

impl ProverTester for MultiBatchProverTester {
    type Prover = BatchProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const ASSETS_DIR: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        unimplemented!()
    }

    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverVerifier>::ProvingTask>>
    {
        todo!("BatchProverTester: gen_multi_proving_tasks not implemented")
    }
}
