use std::path::Path;

use scroll_zkvm_prover::{
    BundleProverType, ProverType, task::bundle::BundleProvingTask, utils::read_json_deep,
};

use crate::{ProverTester, testers::PATH_TESTDATA};

pub struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Prover = BundleProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const DIR_ASSETS: &str = "bundle";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        Ok(BundleProvingTask {
            batch_proofs: vec![
                read_json_deep(Path::new(PATH_TESTDATA).join("proofs").join(
                    "batch-0x60f88f3e46c74362cd93c07724c9ef8e56e391317df6504b905c3c16e81de2e4.json",
                ))?,
                read_json_deep(Path::new(PATH_TESTDATA).join("proofs").join(
                    "batch-0x30d2f51e20e9a4ecd460466af9c81d13daad4fb8d1ca1e42dab30603374f7e5f.json",
                ))?,
            ],
        })
    }
}
