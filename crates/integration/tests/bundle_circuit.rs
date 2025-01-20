use scroll_zkvm_integration::ProverTester;
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
    // Build the ELF binary from the circuit program.
    let elf = BundleProverTester::build()?;

    // Transpile the ELF into a VmExe.
    let (app_config, path_exe) = BundleProverTester::transpile(elf)?;

    // Generate application proving key and get path on disc.
    let path_pk = BundleProverTester::keygen(app_config)?;

    // Setup bundle prover.
    let bundle_prover =
        <BundleProverTester as ProverTester>::Prover::setup(&path_exe, &path_pk, None)?;

    // Generate proving task for the bundle-circuit.
    let task = BundleProverTester::gen_proving_task()?;

    // Construct root proof for the bundle-circuit.
    let proof = bundle_prover.gen_proof(&task)?;

    // Verify proof.
    bundle_prover.verify_proof(proof)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    unimplemented!()
}
