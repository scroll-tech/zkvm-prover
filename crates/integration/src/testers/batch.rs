use scroll_zkvm_prover::Prover;
use scroll_zkvm_types::{
    batch::{BatchHeader, BatchInfo, BatchWitness, BatchWitnessLegacy, ReferenceHeader},
    chunk::ChunkInfo,
    proof::ProofEnum,
    public_inputs::ForkName,
    utils::serialize_vk,
};

use crate::{
    PartialProvingTask, ProverTester, load_program_commitments, prove_verify,
    testers::chunk::{ChunkTaskGenerator, preset_chunk_multiple},
    utils::build_batch_witnesses,
};

impl PartialProvingTask for BatchWitness {
    fn identifier(&self) -> String {
        let header_hash = match &self.reference_header {
            ReferenceHeader::V6(h) => h.batch_hash(),
            ReferenceHeader::V7(h) => h.batch_hash(),
            ReferenceHeader::V8(h) => h.batch_hash(),
        };
        header_hash.to_string()
    }

    fn legacy_rkyv_archive(&self) -> eyre::Result<Vec<u8>> {
        Ok(
            rkyv::to_bytes::<rkyv::rancor::Error>(&BatchWitnessLegacy::from(self.clone()))?
                .to_vec(),
        )
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
    pub proof: Option<ProofEnum>,
}

impl BatchTaskGenerator {
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
        prover: &mut Prover,
        child_prover: &mut Prover,
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
        child_prover: &mut Prover,
    ) -> eyre::Result<Vec<ProofEnum>> {
        let mut proofs = Vec::new();
        for chunk_gen in &mut self.chunk_generators {
            let proof = chunk_gen.get_or_build_proof(child_prover)?;
            proofs.push(proof);
        }
        child_prover.reset();
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

        let commitment = load_program_commitments("chunk")?;
        let ret_wit = build_batch_witnesses(
            &chunks,
            &serialize_vk::serialize(&commitment),
            self.last_witness
                .as_ref()
                .map(|wit| (&wit.reference_header).into())
                .unwrap_or_default(),
        )?;

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
