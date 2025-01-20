use std::{fs::File, path::Path};

use sbv::primitives::types::BlockWitness;
use scroll_zkvm_integration::ProverTester;
use scroll_zkvm_prover::{ChunkProver, ProverVerifier};

const PATH_BLOCK_WITNESS: &str = "./testdata";

struct ChunkProverTester;

impl ProverTester for ChunkProverTester {
    type Prover = ChunkProver;

    const PATH_PROJECT_ROOT: &str = "./../circuits/chunk-circuit";

    const PREFIX: &str = "chunk";

    fn gen_witness() -> eyre::Result<<Self::Prover as ProverVerifier>::Witness> {
        (12508460usize..=12508463)
            .map(|block_n| {
                let witness = File::open(Path::new(PATH_BLOCK_WITNESS).join(block_n.to_string()))?;
                Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
            })
            .collect::<eyre::Result<Vec<BlockWitness>>>()
    }
}

#[test]
fn setup_prove_verify() -> eyre::Result<()> {
    // Build the ELF binary from the circuit program.
    let elf = ChunkProverTester::build()?;

    // Transpile the ELF into a VmExe.
    let (app_config, path_exe) = ChunkProverTester::transpile(elf)?;

    // Generate application proving key and get path on disc.
    let path_pk = ChunkProverTester::keygen(app_config)?;

    // Setup chunk prover.
    let chunk_prover = <ChunkProverTester as ProverTester>::Prover::setup(&path_exe, &path_pk)?;

    // Generate some witness for the chunk-circuit.
    let witness = ChunkProverTester::gen_witness()?;

    // Construct root proof for the chunk-circuit.
    let proof = chunk_prover.gen_proof(&witness)?;

    // Verify proof.
    chunk_prover.verify_proof(proof)?;

    Ok(())
}
