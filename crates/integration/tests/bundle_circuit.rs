use scroll_zkvm_integration::{ProverTester, prove_verify_common};
use scroll_zkvm_prover::{BundleProver, ProverVerifier};

struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Prover = BundleProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const PREFIX: &str = "bundle";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        todo!("BundleProverTester: gen_proving_task not implemented")
    }
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    prove_verify_common::<BundleProverTester>()
}

#[test]
fn e2e() -> eyre::Result<()> {
    unimplemented!()
}
