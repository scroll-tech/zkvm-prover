use std::sync::Arc;

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::{NonRootCommittedExe, Sdk, StdIn, config::SdkVmConfig, keygen::AppProvingKey};
use scroll_zkvm_circuit_input_types::chunk::ChunkInfo;

#[cfg(feature = "scroll")]
use sbv::{
    core::ChunkInfo as SbvChunkInfo,
    primitives::{BlockWithSenders, BlockWitness},
};

use crate::{
    Error, WrappedProof,
    proof::{ChunkProofMetadata, RootProof},
    prover::AGG_STARK_PROVING_KEY,
    task::{ProvingTask, chunk::ChunkProvingTask},
};

use crate::{Prover, ProverType};

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<ChunkProverType>;

pub struct ChunkProverType;

impl ProverType for ChunkProverType {
    const NAME: &'static str = "chunk";

    const EVM: bool = false;

    type ProvingTask = ChunkProvingTask;

    type ProofType = RootProof;

    type ProofMetadata = ChunkProofMetadata;

    fn build_proof_metadata(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        let (first, last) = (
            task.block_witnesses
                .first()
                .expect("at least one block in a chunk"),
            task.block_witnesses
                .last()
                .expect("at least one block in a chunk"),
        );
        let withdraw_root = last.withdrawals_root();
        let sbv_chunk_info = {
            let chain_id = first.chain_id;
            let pre_state_root = first.pre_state_root;
            let blocks = task
                .block_witnesses
                .iter()
                .map(|s| s.build_reth_block())
                .collect::<Result<Vec<BlockWithSenders>, _>>()
                .map_err(|e| Error::GenProof(e.to_string()))?;
            SbvChunkInfo::from_blocks_iter(
                chain_id,
                pre_state_root,
                blocks.iter().map(|b| &b.block),
            )
        };
        let chunk_info = ChunkInfo {
            chain_id: sbv_chunk_info.chain_id(),
            prev_state_root: sbv_chunk_info.prev_state_root(),
            post_state_root: sbv_chunk_info.post_state_root(),
            withdraw_root,
            data_hash: sbv_chunk_info.data_hash(),
        };
        Ok(ChunkProofMetadata { chunk_info })
    }

    fn gen_proof(
        app_pk: Arc<AppProvingKey<SdkVmConfig>>,
        app_committed_exe: Arc<NonRootCommittedExe>,
        task: &Self::ProvingTask,
    ) -> Result<WrappedProof<Self::ProofMetadata, Self::ProofType>, Error> {
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::GenProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(&task.block_witnesses)
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let mut stdin = StdIn::default();
        stdin.write_bytes(&serialized);

        let task_id = task.identifier();

        tracing::debug!(name: "generate_root_proof", ?task_id);
        let proof = Sdk
            .generate_root_verifier_input(
                Arc::clone(&app_pk),
                Arc::clone(&app_committed_exe),
                agg_stark_pk.clone(),
                stdin,
            )
            .map_err(|e| Error::GenProof(e.to_string()))?;

        tracing::debug!(name: "construct_metadata", ?task_id);
        let metadata = Self::build_proof_metadata(task)?;

        let wrapped_proof = WrappedProof::new(metadata, proof);

        Ok(wrapped_proof)
    }

    fn verify_proof(
        proof: &WrappedProof<Self::ProofMetadata, Self::ProofType>,
    ) -> Result<(), Error> {
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::VerifyProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let root_verifier_pk = &agg_stark_pk.root_verifier_pk;
        let vm = SingleSegmentVmExecutor::new(root_verifier_pk.vm_pk.vm_config.clone());
        let exe: &VmCommittedExe<_> = &root_verifier_pk.root_committed_exe;

        let _ = vm
            .execute_and_compute_heights(exe.exe.clone(), proof.proof.write())
            .map_err(|e| Error::VerifyProof(e.to_string()))?;

        Ok(())
    }
}
