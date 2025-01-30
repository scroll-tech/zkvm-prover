use std::path::Path;

use scroll_zkvm_prover::{BatchProverType, ProverType, utils::read_json_deep};

use crate::{ProverTester, testers::PATH_TESTDATA};

pub struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        Ok(read_json_deep(
            Path::new(PATH_TESTDATA).join("batch-task.json"),
        )?)
    }
}

pub struct MultiBatchProverTester;

impl ProverTester for MultiBatchProverTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        unreachable!("Use gen_multi_proving_tasks");
    }

    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        Ok(vec![
            read_json_deep(Path::new(PATH_TESTDATA).join("batch-task-multi-1.json"))?,
            read_json_deep(Path::new(PATH_TESTDATA).join("batch-task-multi-2.json"))?,
        ])
    }
}
