mod verifier;
use scroll_zkvm_integration::{
    ProverTester,
    testers::{batch::BatchProverTester, bundle::BundleProverTester, chunk::ChunkProverTester},
};
use scroll_zkvm_prover::{BatchProverType, BundleProverType, ChunkProverType};
use verifier::dump_verifier;

fn write_commitments(commitments: [[u32; 8]; 2], output: &str) {
    let content = format!(
        "pub const EXE_COMMIT: [u32; 8] = {:?};\npub const LEAF_COMMIT: [u32; 8] = {:?};\n",
        commitments[0], commitments[1]
    );
    std::fs::write(output, content).unwrap();
}

pub fn main() {
    let cwd = std::env::current_dir().unwrap();
    println!("current dir: {}", cwd.display());
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // change cwd to manifest_dir
    std::env::set_current_dir(manifest_dir).unwrap();
    let metadata = cargo_metadata::MetadataCommand::new().exec().unwrap();
    let workspace_dir = metadata.workspace_root;
    println!("workspace dir: {}", workspace_dir);

    // dump_verifier(&format!("{workspace_dir}/crates/build-guest/root_verifier.asm"));

    let chunk_elf = ChunkProverTester::build().unwrap();
    let output_path = format!("{workspace_dir}/crates/circuits/chunk-circuit/openvm");
    let (chunk_config_path, _, chunk_exe_path) =
        ChunkProverTester::transpile(chunk_elf, Some(output_path.into())).unwrap();
    let (_, _, chunk_commitments) =
        scroll_zkvm_prover::Prover::<ChunkProverType>::init(chunk_exe_path, chunk_config_path)
            .unwrap();
    write_commitments(
        chunk_commitments,
        format!("{workspace_dir}/crates/circuits/batch-circuit/src/child_commitments.rs").as_str(),
    );

    let batch_elf = BatchProverTester::build().unwrap();
    let output_path = format!("{workspace_dir}/crates/circuits/batch-circuit/openvm");
    let (batch_config_path, _, batch_exe_path) =
        BatchProverTester::transpile(batch_elf, Some(output_path.into())).unwrap();
    let (_, _, batch_commitments) =
        scroll_zkvm_prover::Prover::<BatchProverType>::init(batch_exe_path, batch_config_path)
            .unwrap();
    write_commitments(
        batch_commitments,
        format!("{workspace_dir}/crates/circuits/bundle-circuit/src/child_commitments.rs").as_str(),
    );

    let bundle_elf = BundleProverTester::build().unwrap();
    let output_path = format!("{workspace_dir}/crates/circuits/bundle-circuit/openvm");
    let (bundle_config_path, _, bundle_exe_path) =
        BundleProverTester::transpile(bundle_elf, Some(output_path.into())).unwrap();
    let (_, _, _bundle_commitments) =
        scroll_zkvm_prover::Prover::<BundleProverType>::init(bundle_exe_path, bundle_config_path)
            .unwrap();

    println!("build guest done");
}
