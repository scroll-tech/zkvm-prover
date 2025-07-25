use std::fs::File;
use std::path::Path;
use std::sync::LazyLock;
use cargo_metadata::MetadataCommand;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use rkyv::rancor;
use sbv_primitives::types::BlockWitness;
use scroll_zkvm_risc0_methods::{CHUNK_GUEST_ELF, CHUNK_GUEST_ID};
use scroll_zkvm_types_base::fork_name::ForkName;
use scroll_zkvm_types_chunk::ChunkWitness;

pub static WORKSPACE_ROOT: LazyLock<&Path> = LazyLock::new(|| {
    let path = MetadataCommand::new()
        .no_deps()
        .exec()
        .expect("failed to execute cargo-metadata")
        .workspace_root
        .into_std_path_buf();
    eprintln!("PROJECT_ROOT_DIR = {}", path.display());
    Box::leak(path.into_boxed_path())
});


fn main() {
    let mut env_builder = ExecutorEnv::builder();

    let dir = WORKSPACE_ROOT.join("crates/integration/testdata/feynman/witnesses");
    let block_witnesses = (16525000usize..=16525003usize)
        .into_iter()
        .map(|block|{
            let path = dir.join(format!("{}.json", block));
            serde_json::from_reader::<_, BlockWitness>(File::open(path).unwrap()).unwrap()
        })
        .collect::<Vec<_>>();

    let witness = ChunkWitness::new(
        &block_witnesses,
        Default::default(),
        ForkName::Feynman,
    );
    let serialized_witness = rkyv::to_bytes::<rancor::BoxedError>(&witness)
        .expect("failed to serialize chunk witness");
    let length = serialized_witness.len() as u32;
    env_builder.write(&length).unwrap();
    env_builder.write_slice(serialized_witness.as_slice());

    let env = env_builder.build().unwrap();
    let prover = default_prover();
    let prove_info = prover
        .prove_with_opts(env, CHUNK_GUEST_ELF, &ProverOpts::succinct())
        .unwrap();
    println!("{:#?}", prove_info.stats);

    let receipt = prove_info.receipt;
    receipt
        .verify(CHUNK_GUEST_ID)
        .unwrap();
}
