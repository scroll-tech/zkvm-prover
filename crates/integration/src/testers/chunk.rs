use std::{
    fs::File,
    path::{Path, PathBuf},
};

use sbv_primitives::{B256, types::BlockWitness};
use scroll_zkvm_prover::Prover;
use scroll_zkvm_types::{
    chunk::{ChunkInfo, ChunkWitness},
    proof::ProofEnum,
    public_inputs::ForkName,
};

use crate::{
    PartialProvingTask, ProverTester, TestTaskBuilder, prove_verify, testdata_fork_directory,
    testers::PATH_TESTDATA, testing_hardfork,
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
    pub block_range: std::ops::Range<u64>,
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

    fn gen_witnesses_proof(&self, prover: &Prover) -> eyre::Result<ProofEnum> {
        prove_verify::<ChunkProverTester>(prover, &self.gen_proving_witnesses()?, &[])
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
