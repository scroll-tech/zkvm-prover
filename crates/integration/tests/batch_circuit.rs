use scroll_zkvm_integration::{ProverTester, prove_verify_common};
use scroll_zkvm_prover::{BatchProver, ProverVerifier};

struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Prover = BatchProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const PREFIX: &str = "batch";

    fn gen_proving_task() -> eyre::Result<<Self::Prover as ProverVerifier>::ProvingTask> {
        todo!("BatchProverTester: gen_proving_task not implemented")
    }
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    prove_verify_common::<BatchProverTester>()
}

#[test]
fn e2e() -> eyre::Result<()> {
    unimplemented!()
}
