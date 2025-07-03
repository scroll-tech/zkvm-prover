use std::path::Path;

use scroll_zkvm_prover::{ProverType, task::bundle::BundleProvingTask, utils::read_json_deep};

// Only related to hardcoded commitments. Can be refactored later.
use scroll_zkvm_prover::BundleProverTypeEuclidV2 as BundleProverType;

use crate::{ProverTester, testers::PATH_TESTDATA, utils::testing_hardfork};

pub struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Prover = BundleProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const DIR_ASSETS: &str = "bundle";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        Ok(BundleProvingTask {
            batch_proofs: vec![
                read_json_deep(Path::new(PATH_TESTDATA).join("proofs").join(
                    "batch-0x6a2d14504ccc86a2d1a3fb00f95e50cf2de80230fc51306d16b5f4ccc17b8e73.json",
                ))?,
                read_json_deep(Path::new(PATH_TESTDATA).join("proofs").join(
                    "batch-0x5f769da6d14efecf756c2a82c164416f31b3986d6c701479107acb1bcd421b21.json",
                ))?,
            ],
            bundle_info: None,
            fork_name: testing_hardfork().to_string(),
        })
    }
}

pub struct BundleLocalTaskTester;

impl ProverTester for BundleLocalTaskTester {
    type Prover = BundleProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const DIR_ASSETS: &str = "bundle";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        Ok(read_json_deep(
            Path::new(PATH_TESTDATA).join("bundle-task.json"),
        )?)
    }
}
