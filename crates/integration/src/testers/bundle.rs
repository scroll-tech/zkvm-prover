use scroll_zkvm_prover::{BundleProverType, ProverType};

use crate::ProverTester;

pub struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Prover = BundleProverType;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const ASSETS_DIR: &str = "bundle";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverType>::ProvingTask> {
        todo!("BundleProverTester: gen_proving_task not implemented")
    }
}
