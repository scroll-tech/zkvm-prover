use std::path::Path;

use scroll_zkvm_prover::{BatchProverType, ProverType};

use crate::ProverTester;

const PATH_BATCH_WITNESS: &str = "./testdata/batch-task.json";

pub struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const ASSETS_DIR: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        let path_witness = Path::new(PATH_BATCH_WITNESS);
        let witness = std::fs::File::open(path_witness)?;
        Ok(serde_json::from_reader(witness)?)
    }
}

pub struct MultiBatchProverTester;

impl ProverTester for MultiBatchProverTester {
    type Prover = BatchProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const ASSETS_DIR: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        unimplemented!()
    }

    fn gen_multi_proving_tasks() -> eyre::Result<Vec<<Self::Prover as ProverType>::ProvingTask>> {
        todo!("BatchProverTester: gen_multi_proving_tasks not implemented")
    }
}
