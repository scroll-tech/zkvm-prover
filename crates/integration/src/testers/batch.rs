use scroll_zkvm_types::{
    batch::{BatchHeader, BatchInfo, BatchWitness, ReferenceHeader},
    chunk::ChunkInfo,
    proof::ProofEnum,
    public_inputs::ForkName,
};

use crate::{
    PartialProvingTask, ProverTester, TestTaskBuilder,
    testers::{
        UnsafeSendWrappedProver,
        chunk::{ChunkProverTester, ChunkTaskGenerator, preset_chunk_multiple},
    },
    utils::{build_batch_witnesses, metadata_from_chunk_witnesses},
};

use std::sync::{Mutex, OnceLock};

impl PartialProvingTask for BatchWitness {
    fn identifier(&self) -> String {
        let header_hash = match &self.reference_header {
            ReferenceHeader::V6(h) => h.batch_hash(),
            ReferenceHeader::V7(h) => h.batch_hash(),
            ReferenceHeader::V8(h) => h.batch_hash(),
        };
        header_hash.to_string()
    }

    fn write_guest_input(&self, stdin: &mut openvm_sdk::StdIn) -> Result<(), rkyv::rancor::Error> {
        let b = rkyv::to_bytes::<rkyv::rancor::Error>(self)?;
        stdin.write_bytes(b.as_slice());
        Ok(())
    }

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }
}

pub struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Metadata = BatchInfo;

    type Witness = BatchWitness;

    const NAME: &str = "batch";

    const PATH_PROJECT_ROOT: &str = "crates/circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";
}

impl BatchProverTester {
    fn instrinsic_chunk_prover() -> eyre::Result<&'static Mutex<UnsafeSendWrappedProver>> {
        static CHUNK_PROVER: OnceLock<eyre::Result<Mutex<UnsafeSendWrappedProver>>> =
            OnceLock::new();
        CHUNK_PROVER
            .get_or_init(|| {
                ChunkProverTester::load_prover(false)
                    .map(UnsafeSendWrappedProver)
                    .map(Mutex::new)
            })
            .as_ref()
            .map_err(|e| eyre::eyre!("{e}"))
    }
}

#[derive(Debug, Clone)]
pub struct BatchTaskGenerator {
    result: OnceLock<BatchWitness>,
    chunk_generators: Vec<ChunkTaskGenerator>,
    last_witness: Option<BatchWitness>,
}

impl TestTaskBuilder<BatchProverTester> for BatchTaskGenerator {
    fn gen_proving_witnesses(&self) -> eyre::Result<BatchWitness> {
        Ok(if let Some(r) = self.result.get() {
            r.clone()
        } else {
            let r = self.calculate_batch_witness()?;
            self.result.set(r.clone()).ok();
            r
        })
    }

    fn gen_agg_proofs(&self) -> eyre::Result<Vec<ProofEnum>> {
        let chunk_prover = &BatchProverTester::instrinsic_chunk_prover()?
            .lock()
            .unwrap()
            .0;
        let chunk_proofs = self
            .chunk_generators
            .iter()
            .map(|generator| generator.gen_witnesses_proof(chunk_prover))
            .collect::<Result<Vec<ProofEnum>, _>>()?;
        Ok(chunk_proofs)
    }
}

impl BatchTaskGenerator {
    fn calculate_batch_witness(&self) -> eyre::Result<BatchWitness> {
        let mut chunks = Vec::new();
        let mut chunk_infos = Vec::new();
        let mut last_info: Option<&ChunkInfo> = self
            .last_witness
            .as_ref()
            .and_then(|wit| wit.chunk_infos.last());

        for chunk_generator in &self.chunk_generators {
            let chunk_wit = chunk_generator.gen_proving_witnesses()?;
            let info = metadata_from_chunk_witnesses(&chunk_wit)?;

            if let Some(last_info) = last_info {
                // validate some data
                assert_eq!(
                    last_info.post_state_root, info.prev_state_root,
                    "state root"
                );
                assert_eq!(last_info.chain_id, info.chain_id, "chain id");
                assert_eq!(
                    last_info.initial_block_number + last_info.block_ctxs.len() as u64,
                    info.initial_block_number,
                    "block number",
                );
                assert_eq!(
                    last_info.post_msg_queue_hash, info.prev_msg_queue_hash,
                    "msg queue hash"
                );
            }

            chunks.push(chunk_wit);
            chunk_infos.push(info);
            last_info = chunk_infos.last();
        }

        Ok(build_batch_witnesses(
            &chunks,
            &chunk_infos,
            &BatchProverTester::instrinsic_chunk_prover()?
                .lock()
                .unwrap()
                .0
                .get_app_vk(),
            self.last_witness
                .as_ref()
                .map(|wit| (&wit.reference_header).into())
                .unwrap_or_default(),
        ))
    }

    /// accept a series of ChunkTaskGenerator
    pub fn from_chunk_tasks(
        ref_chunks: &[ChunkTaskGenerator],
        last_witness: Option<BatchWitness>,
    ) -> Self {
        Self {
            result: OnceLock::new(),
            chunk_generators: ref_chunks.to_vec(),
            last_witness,
        }
    }
}

/// create canonical tasks from a series of block range
pub fn create_canonical_tasks<'a>(
    chunk_tasks: impl Iterator<Item = &'a [ChunkTaskGenerator]>,
) -> eyre::Result<Vec<BatchTaskGenerator>> {
    let mut ret: Vec<BatchTaskGenerator> = Vec::new();
    for chunks in chunk_tasks {
        let canonical_generator = BatchTaskGenerator::from_chunk_tasks(
            chunks,
            ret.last().map(|g| g.gen_proving_witnesses()).transpose()?,
        );
        ret.push(canonical_generator);
    }
    Ok(ret)
}

/// preset examples for single task
pub fn preset_batch() -> BatchTaskGenerator {
    BatchTaskGenerator::from_chunk_tasks(&preset_chunk_multiple(), None)
}

/// preset examples for multiple task
pub fn preset_batch_multiple() -> Vec<BatchTaskGenerator> {
    static PRESET_RESULT: std::sync::OnceLock<Vec<BatchTaskGenerator>> = std::sync::OnceLock::new();

    PRESET_RESULT
        .get_or_init(|| {
            let chunks = preset_chunk_multiple();
            assert!(chunks.len() > 2);
            create_canonical_tasks([&chunks[0..1], &chunks[1..]].into_iter())
                .expect("must success for preset collections")
        })
        .clone()
}
