use profile_lib::*;
use rkyv::rancor;
use sbv_primitives::types::BlockWitness;
use scroll_zkvm_types_base::fork_name::ForkName;
use sp1_sdk::{CpuProver, SP1Stdin, include_elf};

const ELF: &[u8] = include_elf!("sp1-profile");

const TRACES: &[&str] = &[
    include_str!("../../../integration/testdata/feynman/witnesses/16525000.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525001.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525002.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525003.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525004.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525005.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525006.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525007.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525008.json"),
    include_str!("../../../integration/testdata/feynman/witnesses/16525009.json"),
];

fn main() {
    let client = CpuProver::new();
    let mut stdin = SP1Stdin::new();

    let blocks: Vec<BlockWitness> = TRACES
        .into_iter()
        .map(|t| serde_json::from_str(t).unwrap())
        .collect();
    let compression_ratios = blocks
        .iter()
        .map(|block| block.compression_ratios())
        .collect();
    let witness = ChunkWitness {
        blocks,
        prev_msg_queue_hash: Default::default(),
        fork_name: ForkName::Feynman,
        compression_ratios,
        state_commit_mode: StateCommitMode::Chunk,
    };
    let witness = rkyv::to_bytes::<rancor::Error>(&witness).unwrap();
    stdin.write_vec(witness.to_vec());

    let (_, report) = client.execute(ELF, &stdin).run().unwrap();

    println!("{:?}", report.cycle_tracker);
    println!("{:?}", report.invocation_tracker);
}
