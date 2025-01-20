use scroll_zkvm_integration::ProverTester;
use scroll_zkvm_prover::{BatchProver, ProverVerifier};

struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Prover = BatchProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/batch-circuit";

    const PREFIX: &str = "batch";

    fn gen_witness() -> eyre::Result<<Self::Prover as ProverVerifier>::Witness> {
        todo!("BatchProverTester: gen_witness not implemented")
    }
}

#[test]
fn e2e_batch_prover() -> eyre::Result<()> {
    // Build the ELF binary from the circuit program.
    let elf = BatchProverTester::build()?;

    // Transpile the ELF into a VmExe.
    let (app_config, path_exe) = BatchProverTester::transpile(elf)?;

    // Generate application proving key and get path on disc.
    let path_pk = BatchProverTester::keygen(app_config)?;

    // Setup batch prover.
    let batch_prover = <BatchProverTester as ProverTester>::Prover::setup(&path_exe, &path_pk)?;

    // Generate some witness for the batch-circuit.
    let witness = BatchProverTester::gen_witness()?;

    // Construct root proof for the batch-circuit.
    let proof = batch_prover.gen_proof(&witness)?;

    // Verify proof.
    batch_prover.verify_proof(proof)?;

    Ok(())
}
