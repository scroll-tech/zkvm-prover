use std::{
    fs::File,
    path::{Path, PathBuf},
};

use sbv_primitives::{B256, BlockWitness};
use scroll_zkvm_types::{
    chunk::{ChunkInfo, ChunkWitness},
    proof::ProofEnum,
    public_inputs::ForkName,
};

use crate::{
    PartialProvingTask, ProverTester, TestTaskBuilder, testdata_fork_directory,
    testers::PATH_TESTDATA, testing_hardfork, utils::metadata_from_chunk_witnesses,
};

/// Load a file <block_n>.json in the <PATH_BLOCK_WITNESS> directory.
pub fn read_block_witness_from_testdata(block_n: usize) -> eyre::Result<BlockWitness> {
    read_block_witness(
        Path::new(PATH_TESTDATA)
            .join(testdata_fork_directory())
            .join("witnesses")
            .join(format!("{}.json", block_n)),
    )
}

/// Utility function to read and deserialize block witness given the block number.
pub fn read_block_witness<P>(path_witness: P) -> eyre::Result<BlockWitness>
where
    P: AsRef<Path>,
{
    if !path_witness.as_ref().exists() {
        println!("File not found: {:?}", path_witness.as_ref());
        return Err(eyre::eyre!("File not found: {:?}", path_witness.as_ref()));
    }
    let witness = File::open(path_witness)?;
    Ok(serde_json::from_reader::<_, BlockWitness>(witness)?)
}

pub struct ChunkProverTester;

impl PartialProvingTask for ChunkWitness {
    fn identifier(&self) -> String {
        let (first, last) = (
            self.blocks.first().expect("MUST NOT EMPTY").header.number,
            self.blocks.last().expect("MUST NOT EMPTY").header.number,
        );
        format!("{first}-{last}")
    }

    fn write_guest_input(&self, stdin: &mut openvm_sdk::StdIn) -> Result<(), rkyv::rancor::Error> {
        stdin.write_bytes(self.rkyv_serialize(None)?.as_slice());
        Ok(())
    }

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }
}

impl ProverTester for ChunkProverTester {
    type Metadata = ChunkInfo;

    type Witness = ChunkWitness;

    const NAME: &str = "chunk";

    const PATH_PROJECT_ROOT: &str = "crates/circuits/chunk-circuit";

    const DIR_ASSETS: &str = "chunk";
}

/// Generator collect a range of block witnesses from test data
#[derive(Clone, Debug)]
pub struct ChunkTaskGenerator {
    pub block_range: std::ops::RangeInclusive<u64>,
    pub prev_message_hash: Option<B256>,
}

impl TestTaskBuilder<ChunkProverTester> for ChunkTaskGenerator {
    fn gen_proving_witnesses(&self) -> eyre::Result<ChunkWitness> {
        let paths: Vec<PathBuf> = self
            .block_range
            .clone()
            .map(|block_n| {
                Path::new(PATH_TESTDATA)
                    .join(testdata_fork_directory())
                    .join("witnesses")
                    .join(format!("{}.json", block_n))
            })
            .collect();

        let block_witnesses = paths
            .iter()
            .map(read_block_witness)
            .collect::<eyre::Result<Vec<BlockWitness>>>()?;
        Ok(ChunkWitness::new(
            &block_witnesses,
            self.prev_message_hash
                .unwrap_or_else(|| B256::repeat_byte(1u8)),
            testing_hardfork(),
        ))
    }

    fn gen_agg_proofs(&self) -> eyre::Result<Vec<ProofEnum>> {
        Ok(Vec::new())
    }
}

/// helper func to gen a series of proving tasks, specified by the block number
pub fn get_witness_from_env_or_builder(
    fallback_generator: &ChunkTaskGenerator,
) -> eyre::Result<ChunkWitness> {
    let paths: Vec<PathBuf> = match std::env::var("TRACE_PATH") {
        Ok(paths) => glob::glob(&paths)?.filter_map(|entry| entry.ok()).collect(),
        Err(_) => return fallback_generator.gen_proving_witnesses(),
    };

    let block_witnesses = paths
        .iter()
        .map(read_block_witness)
        .collect::<eyre::Result<Vec<BlockWitness>>>()?;
    Ok(ChunkWitness::new(
        &block_witnesses,
        B256::repeat_byte(1u8),
        testing_hardfork(),
    ))
}

/// preset examples for single task
pub fn preset_chunk() -> ChunkTaskGenerator {
    let block_range = match testing_hardfork() {
        ForkName::EuclidV1 => 12508460u64..=12508463u64,
        ForkName::EuclidV2 => 1u64..=4u64,
        ForkName::Feynman => 16525000u64..=16525003u64,
    };

    ChunkTaskGenerator {
        block_range,
        prev_message_hash: None,
    }
}

/// create canonical tasks from a series of block range
pub fn create_canonical_tasks(
    ranges: impl Iterator<Item = std::ops::RangeInclusive<u64>>,
) -> eyre::Result<Vec<ChunkTaskGenerator>> {
    let mut ret = Vec::new();
    let mut prev_message_hash = None;
    for r in ranges {
        let canonical_generator = ChunkTaskGenerator {
            block_range: r,
            prev_message_hash,
        };
        let chunk_wit = canonical_generator.gen_proving_witnesses()?;
        let info = metadata_from_chunk_witnesses(&chunk_wit)?;

        prev_message_hash = Some(info.post_msg_queue_hash);
        ret.push(canonical_generator);
    }

    Ok(ret)
}

/// preset examples for multiple task
pub fn preset_chunk_multiple() -> Vec<ChunkTaskGenerator> {
    static PRESET_RESULT: std::sync::OnceLock<Vec<ChunkTaskGenerator>> = std::sync::OnceLock::new();

    PRESET_RESULT
        .get_or_init(|| {
            create_canonical_tasks(
                match testing_hardfork() {
                    ForkName::EuclidV1 => vec![
                        12508460u64..=12508460u64,
                        12508461u64..=12508461u64,
                        12508462u64..=12508463u64,
                    ],
                    ForkName::EuclidV2 => vec![1u64..=1u64, 2u64..=2u64, 3u64..=4u64],
                    ForkName::Feynman => vec![
                        16525000u64..=16525000u64,
                        16525001u64..=16525001u64,
                        16525002u64..=16525003u64,
                    ],
                }
                .into_iter(),
            )
            .expect("must success for preset collections")
        })
        .clone()
}
