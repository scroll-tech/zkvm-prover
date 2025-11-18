use scroll_zkvm_types::{
    batch::{BatchHeader, BatchInfo, BatchWitness, LegacyBatchWitness, ReferenceHeader},
    chunk::ChunkInfo,
    proof::ProofEnum,
    public_inputs::{ForkName, Version},
    utils::serialize_vk,
};

use crate::{
    PROGRAM_COMMITMENTS, PartialProvingTask, ProverTester, TaskProver, prove_verify,
    testers::chunk::{ChunkTaskGenerator, preset_chunk_multiple, preset_chunk_validium},
    utils::{build_batch_witnesses, build_batch_witnesses_validium},
};

impl PartialProvingTask for BatchWitness {
    fn identifier(&self) -> String {
        let header_hash = match &self.reference_header {
            ReferenceHeader::V6(h) => h.batch_hash(),
            ReferenceHeader::V7_V8_V9(h) => h.batch_hash(),
            ReferenceHeader::Validium(h) => h.batch_hash(),
        };
        header_hash.to_string()
    }

    fn legacy_rkyv_archive(&self) -> eyre::Result<Vec<u8>> {
        let witness_legacy = LegacyBatchWitness::from(self.clone());
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&witness_legacy)?;
        Ok(bytes.to_vec())
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

#[derive(Clone)]
pub struct BatchTaskGenerator {
    witness: Option<BatchWitness>,
    chunk_generators: Vec<ChunkTaskGenerator>,
    last_witness: Option<BatchWitness>,
    proof: Option<ProofEnum>,
}

impl BatchTaskGenerator {
    pub fn version(&self) -> Version {
        if let Some(wit) = self.witness.as_ref() {
            return Version::from(wit.version);
        }
        self.chunk_generators
            .first()
            .expect("at least 1 chunk in a batch")
            .version
    }

    pub fn get_or_build_witness(&mut self) -> eyre::Result<BatchWitness> {
        if self.witness.is_some() {
            return Ok(self.witness.clone().unwrap());
        }
        let witness = self.calculate_witness()?;
        self.witness.replace(witness.clone());
        Ok(witness)
    }

    pub fn get_or_build_proof(
        &mut self,
        prover: &mut impl TaskProver,
        child_prover: &mut impl TaskProver,
    ) -> eyre::Result<ProofEnum> {
        if let Some(proof) = &self.proof {
            return Ok(proof.clone());
        }
        let wit = self.get_or_build_witness()?;
        let agg_proofs = self.get_or_build_child_proofs(child_prover)?;
        let proof = prove_verify::<BatchProverTester>(prover, &wit, &agg_proofs)?;
        self.proof.replace(proof.clone());
        Ok(proof)
    }

    pub fn get_or_build_child_proofs(
        &mut self,
        child_prover: &mut impl TaskProver,
    ) -> eyre::Result<Vec<ProofEnum>> {
        let mut proofs = Vec::new();
        for chunk_gen in &mut self.chunk_generators {
            let proof = chunk_gen.get_or_build_proof(child_prover)?;
            proofs.push(proof);
        }
        Ok(proofs)
    }

    fn calculate_witness(&mut self) -> eyre::Result<BatchWitness> {
        let mut last_info: Option<&ChunkInfo> = self
            .last_witness
            .as_ref()
            .and_then(|wit| wit.chunk_infos.last());

        let chunks = self
            .chunk_generators
            .iter_mut()
            .map(|g| g.get_or_build_witness())
            .collect::<eyre::Result<Vec<_>>>()?;

        let commitment = PROGRAM_COMMITMENTS["chunk"];

        let ret_wit = if chunks
            .first()
            .expect("at least 1 chunk in batch")
            .version()
            .is_validium()
        {
            build_batch_witnesses_validium(
                &chunks,
                &serialize_vk::serialize(&commitment),
                self.last_witness
                    .as_ref()
                    .map(|wit| (&wit.reference_header).into())
                    .unwrap_or_default(),
            )?
        } else {
            build_batch_witnesses(
                &chunks,
                &serialize_vk::serialize(&commitment),
                self.last_witness
                    .as_ref()
                    .map(|wit| (&wit.reference_header).into())
                    .unwrap_or_default(),
            )?
        };

        // sanity check
        for info in &ret_wit.chunk_infos {
            if let Some(last_info) = last_info {
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

            last_info.replace(info);
        }

        Ok(ret_wit)
    }

    /// accept a series of ChunkTaskGenerator
    pub fn from_chunk_tasks(
        ref_chunks: &[ChunkTaskGenerator],
        last_witness: Option<BatchWitness>,
    ) -> Self {
        Self {
            witness: None,
            chunk_generators: ref_chunks.to_vec(),
            last_witness,
            proof: None,
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
            ret.last_mut()
                .map(|g| g.get_or_build_witness())
                .transpose()?,
        );
        ret.push(canonical_generator);
    }
    Ok(ret)
}

/// preset examples for single task
pub fn preset_batch() -> BatchTaskGenerator {
    BatchTaskGenerator::from_chunk_tasks(&preset_chunk_multiple(), None)
}

pub fn preset_batch_validium() -> Vec<BatchTaskGenerator> {
    let validium_chunks = preset_chunk_validium();
    assert_eq!(validium_chunks.len(), 5);
    create_canonical_tasks(
        [
            &validium_chunks[0..=1],
            &validium_chunks[2..=3],
            &validium_chunks[4..=4],
        ]
        .into_iter(),
    )
    .expect("must succeed for preset collection")
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
