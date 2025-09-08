use std::{
    fs::File,
    io::{Seek, SeekFrom},
    path::{Path, PathBuf},
};

use sbv_core::BlockWitness;
use sbv_primitives::{B256, types::consensus::TxL1Message};
use scroll_zkvm_prover::{Prover, utils::read_json};
use scroll_zkvm_types::{
    chunk::{ChunkInfo, ChunkWitness, LegacyChunkWitness, SecretKey},
    proof::ProofEnum,
    public_inputs::{ForkName, Version},
};

use crate::{
    PartialProvingTask, ProverTester, prove_verify, testdata_fork_directory,
    testers::PATH_TESTDATA, testing_hardfork, testing_version,
    utils::metadata_from_chunk_witnesses,
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
    let mut witness = File::open(path_witness)?;
    if let Ok(witness) = serde_json::from_reader::<_, BlockWitness>(&mut witness) {
        Ok(witness)
    } else {
        witness.seek(SeekFrom::Start(0))?;
        Ok(BlockWitness::from(serde_json::from_reader::<
            _,
            sbv_primitives::legacy_types::BlockWitness,
        >(witness)?))
    }
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

    fn legacy_rkyv_archive(&self) -> eyre::Result<Vec<u8>> {
        let witness_legacy = LegacyChunkWitness::from(self.clone());
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&witness_legacy)?;
        Ok(bytes.to_vec())
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
#[derive(Clone, Default)]
pub struct ChunkTaskGenerator {
    pub version: Version,
    pub block_range: Vec<u64>,
    pub prev_message_hash: Option<B256>,
    pub witness: Option<ChunkWitness>,
    pub proof: Option<ProofEnum>,
}

impl ChunkTaskGenerator {
    pub fn get_or_build_witness(&mut self) -> eyre::Result<ChunkWitness> {
        if let Some(witness) = &self.witness {
            return Ok(witness.clone());
        }

        let witness = self.calculate_witness()?;
        self.witness = Some(witness.clone());
        Ok(witness)
    }

    pub fn get_or_build_proof(&mut self, prover: &mut Prover) -> eyre::Result<ProofEnum> {
        if let Some(proof) = &self.proof {
            return Ok(proof.clone());
        }
        let wit = self.get_or_build_witness()?;
        let proof = prove_verify::<ChunkProverTester>(prover, &wit, &[])?;
        self.proof.replace(proof.clone());
        Ok(proof)
    }

    pub fn calculate_witness(&mut self) -> eyre::Result<ChunkWitness> {
        let dir_name = if self.version.is_validium() {
            "validium"
        } else {
            self.version.fork.as_str()
        };
        let paths: Vec<PathBuf> = self
            .block_range
            .iter()
            .map(|block_n| {
                Path::new(PATH_TESTDATA)
                    .join(dir_name)
                    .join("witnesses")
                    .join(format!("{}.json", block_n))
            })
            .collect();

        let block_witnesses = paths
            .iter()
            .map(read_block_witness)
            .collect::<eyre::Result<Vec<BlockWitness>>>()?;

        let witness = if self.version.is_validium() {
            let base_dir = Path::new(PATH_TESTDATA).join("validium").join("witnesses");
            let secret_key = hex::decode(std::env::var("VALIDIUM_KEY")?)?;
            let secret_key = SecretKey::try_from_bytes(&secret_key)?;
            let validium_txs = self
                .block_range
                .iter()
                .map(|blk| read_json(base_dir.join(format!("{blk}_validium_txs.json"))))
                .collect::<Result<Vec<Vec<TxL1Message>>, _>>()?;
            ChunkWitness::new_validium(
                self.version.as_version_byte(),
                &block_witnesses,
                self.prev_message_hash
                    .unwrap_or_else(|| B256::repeat_byte(1u8)),
                self.version.fork,
                validium_txs,
                secret_key,
            )
        } else {
            ChunkWitness::new_scroll(
                self.version.as_version_byte(),
                &block_witnesses,
                self.prev_message_hash
                    .unwrap_or_else(|| B256::repeat_byte(1u8)),
                testing_hardfork(),
            )
        };

        Ok(witness)
    }
}

/// helper func to gen a series of proving tasks, specified by the block number
pub fn get_witness_from_env_or_builder(
    fallback_generator: &mut ChunkTaskGenerator,
) -> eyre::Result<ChunkWitness> {
    let paths: Vec<PathBuf> = match std::env::var("TRACE_PATH") {
        Ok(paths) => glob::glob(&paths)?.filter_map(|entry| entry.ok()).collect(),
        Err(_) => return fallback_generator.get_or_build_witness(),
    };

    let block_witnesses = paths
        .iter()
        .map(read_block_witness)
        .collect::<eyre::Result<Vec<BlockWitness>>>()?;

    let version = testing_version().as_version_byte();

    Ok(ChunkWitness::new_scroll(
        version,
        &block_witnesses,
        B256::repeat_byte(1u8),
        testing_hardfork(),
    ))
}

/// preset examples for single task
pub fn preset_chunk() -> ChunkTaskGenerator {
    let (version, block_range) = match testing_hardfork() {
        ForkName::EuclidV1 => (Version::euclid_v1(), 12508460u64..=12508463u64),
        ForkName::EuclidV2 => (Version::euclid_v2(), 1u64..=4u64),
        ForkName::Feynman => (Version::feynman(), 16525000u64..=16525003u64),
    };

    ChunkTaskGenerator {
        version,
        block_range: block_range.collect(),
        ..Default::default()
    }
}

/// create canonical tasks from a series of block range
pub fn create_canonical_tasks(
    version: Version,
    ranges: impl Iterator<Item = std::ops::RangeInclusive<u64>>,
) -> eyre::Result<Vec<ChunkTaskGenerator>> {
    let mut ret = Vec::new();
    let mut prev_message_hash = None;
    for r in ranges {
        let mut canonical_generator = ChunkTaskGenerator {
            version,
            block_range: r.collect(),
            prev_message_hash,
            proof: Default::default(),
            witness: Default::default(),
        };
        let chunk_wit = canonical_generator.get_or_build_witness()?;
        let info = metadata_from_chunk_witnesses(chunk_wit)?;

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
            let (block_range, version) = match testing_hardfork() {
                ForkName::EuclidV1 => (
                    vec![
                        12508460u64..=12508460u64,
                        12508461u64..=12508461u64,
                        12508462u64..=12508463u64,
                    ],
                    Version::euclid_v1(),
                ),
                ForkName::EuclidV2 => (
                    vec![1u64..=1u64, 2u64..=2u64, 3u64..=4u64],
                    Version::euclid_v2(),
                ),
                ForkName::Feynman => (
                    vec![
                        16525000u64..=16525000u64,
                        16525001u64..=16525001u64,
                        16525002u64..=16525003u64,
                    ],
                    Version::feynman(),
                ),
            };
            create_canonical_tasks(version, block_range.into_iter())
                .expect("must success for preset collections")
        })
        .clone()
}

pub fn preset_chunk_validium() -> Vec<ChunkTaskGenerator> {
    let block_range = vec![347..=355, 356..=360, 361..=370, 371..=375, 376..=397];
    create_canonical_tasks(Version::validium_v1(), block_range.into_iter())
        .expect("must succeed for preset collection")
}
