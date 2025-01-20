use scroll_zkvm_integration::ProverTester;
use scroll_zkvm_prover::{BundleProver, ProverVerifier};

struct BundleProverTester;

impl ProverTester for BundleProverTester {
    type Prover = BundleProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/bundle-circuit";

    const PREFIX: &str = "bundle";

    fn gen_witness() -> eyre::Result<<Self::Prover as ProverVerifier>::Witness> {
        todo!("BundleProverTester: gen_witness not implemented")
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
    let bundle_prover = <BundleProverTester as ProverTester>::Prover::setup(&path_exe, &path_pk)?;

    // Generate some witness for the bundle-circuit.
    let witness = BundleProverTester::gen_witness()?;

    // Construct root proof for the bundle-circuit.
    let proof = bundle_prover.gen_proof(&witness)?;

    // Verify proof.
    bundle_prover.verify_proof(proof)?;

    Ok(())
}

#[test]
fn e2e() -> eyre::Result<()> {
    unimplemented!()
}
