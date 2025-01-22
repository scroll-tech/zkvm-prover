use scroll_zkvm_prover::{BundleProver, ProverVerifier};

use crate::ProverTester;

pub struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Prover = BundleProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const PREFIX: &str = "bundle";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        todo!("BundleProverTester: gen_proving_task not implemented")
    }
}
