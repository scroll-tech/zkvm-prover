use scroll_zkvm_prover::Prover;
use scroll_zkvm_types::{
    proof::ProofEnum,
    public_inputs::ForkName,
    chunk::ChunkInfo,
    batch::{BatchInfo, BatchWitness, BatchHeader, ReferenceHeader},
};

use crate::{
    ProverTester, PartialProvingTask, TestTaskBuilder,
    prove_verify,
    testers::{UnsafeSendWrappedProver, chunk::{ChunkProverTester, ChunkTaskGenerator}},
    utils::{build_batch_witnesses, metadata_from_chunk_witnesses, LastHeader},
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
    fn instrinsic_chunk_prover() -> eyre::Result<&'static Mutex<UnsafeSendWrappedProver>>{
        static CHUNK_PROVER: OnceLock<eyre::Result<Mutex<UnsafeSendWrappedProver>>> = OnceLock::new();
        CHUNK_PROVER.get_or_init(||
            ChunkProverTester::load_prover(false)
            .map(UnsafeSendWrappedProver)
            .map(Mutex::new)
            ).as_ref()
            .map_err(|e|eyre::eyre!("{e}"))
    }
}


#[derive(Clone, Debug)]
pub struct BatchTaskGenerator {
    result: OnceLock<BatchWitness>,
    chunk_generators: Vec<ChunkTaskGenerator>,
    last_header: Option<LastHeader>,
}

impl TestTaskBuilder<BatchProverTester> for BatchTaskGenerator {

    fn gen_proving_witnesses(&self) -> eyre::Result<BatchWitness>{
        Ok(self.result.get_or_init(||
            self.calculate_batch_witness().unwrap()
        ).clone())
    }

    fn gen_witnesses_proof(&self, prover: &Prover) -> eyre::Result<ProofEnum>{
        let wit = self.gen_proving_witnesses()?;

        let chunk_prover = &BatchProverTester::instrinsic_chunk_prover()?.lock().unwrap().0;
        let chunk_proofs = self.chunk_generators.iter().map(
            |generator|generator.gen_witnesses_proof(&chunk_prover)
        ).collect::<Result<Vec<ProofEnum>, _>>()?;

        prove_verify::<BatchProverTester>(
            prover,
            &wit,
            &chunk_proofs,
        )
    }
}

impl BatchTaskGenerator {

    fn calculate_batch_witness(&self) -> eyre::Result<BatchWitness> {

        let mut chunks = Vec::new();
        let mut chunk_infos = Vec::new();
        let mut last_info : Option<ChunkInfo> = None;

        for chunk_generator in &self.chunk_generators {

            let canonical_generator = ChunkTaskGenerator {
                block_range: chunk_generator.block_range.clone(),
                prev_message_hash: last_info.as_ref().map(|info|info.post_msg_queue_hash),
            };

            let chunk_wit = canonical_generator.gen_proving_witnesses()?;

            if let Some(info) = &last_info {
                // validate some data
                assert_eq!(info.post_state_root, chunk_wit.blocks[0].pre_state_root, "state root");
                assert_eq!(info.chain_id, chunk_wit.blocks[0].chain_id, "chain id");
                assert_eq!(
                    info.initial_block_number + info.block_ctxs.len() as u64, 
                    chunk_wit.blocks[0].header.number,
                    "block number",
                );
            }            
            let info = metadata_from_chunk_witnesses(&chunk_wit)?;

            last_info.replace(info.clone());
            chunks.push(chunk_wit);
            chunk_infos.push(info);
        }

        Ok(build_batch_witnesses(
            &chunks, 
            &chunk_infos, 
            &BatchProverTester::instrinsic_chunk_prover()?.lock().unwrap().0.get_app_vk(), 
            self.last_header.clone().unwrap_or_default(),
        ))

    }

    /// accept a series of ChunkTaskGenerator, validate them are continuous
    /// and fill a valid prev_message_hash
    pub fn from_chunk_tasks(ref_chunks: &[ChunkTaskGenerator], last_witness: Option<BatchWitness>) -> Self {
        Self {
            result: OnceLock::new(),
            chunk_generators: ref_chunks.to_vec(),
            last_header: last_witness.map(|wit|(&wit.reference_header).into()),
        }

    }
}
