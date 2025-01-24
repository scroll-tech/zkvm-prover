use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::{Sdk, StdIn, config::SdkVmConfig};
use scroll_zkvm_circuit_input_types::chunk::ChunkInfo;
use tracing::{debug, instrument};

#[cfg(feature = "scroll")]
use sbv::{
    core::ChunkInfo as SbvChunkInfo,
    primitives::{BlockWithSenders, BlockWitness},
};

use crate::{
    ChunkProof, Error, Prover, ProverVerifier, WrappedProof,
    proof::ChunkProofMetadata,
    task::{ProvingTask, chunk::ChunkProvingTask},
};

use super::AGG_STARK_PROVING_KEY;

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<SdkVmConfig>;

impl ProverVerifier for ChunkProver {
    type ProvingTask = ChunkProvingTask;

    type Proof = ChunkProof;

    type ProofMetadata = ChunkProofMetadata;

    const PREFIX: &str = "chunk-proof-";

    const EVM: bool = false;

    #[instrument("ChunkProver::setup", skip_all, fields(path_exe, path_pk, cache_dir))]
    fn setup<P: AsRef<Path>>(path_exe: P, path_pk: P, cache_dir: Option<P>) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(path_exe, path_pk)?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            outermost_data: None,
            cache_dir: cache_dir.map(|path| PathBuf::from(path.as_ref())),
        })
    }

    #[instrument("ChunkProver::metadata", skip_all, fields(?task_id = task.identifier()))]
    fn metadata(task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
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

    #[instrument("ChunkProver::gen_proof_inner", skip_all, fields(task_id))]
    fn gen_proof_inner(&self, task: &Self::ProvingTask) -> Result<Self::Proof, Error> {
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

        debug!(name: "generate_root_proof", ?task_id);
        let proof = Sdk
            .generate_root_verifier_input(
                Arc::clone(&self.app_pk),
                Arc::clone(&self.app_committed_exe),
                agg_stark_pk.clone(),
                stdin,
            )
            .map_err(|e| Error::GenProof(e.to_string()))?;

        debug!(name: "construct_metadata", ?task_id);
        let metadata = Self::metadata(task)?;

        let wrapped_proof = WrappedProof::new(metadata, proof);

        Ok(wrapped_proof)
    }

    #[instrument("ChunkProver::verify_proof", skip_all, fields(?metadata = proof.metadata))]
    fn verify_proof(&self, proof: &Self::Proof) -> Result<(), Error> {
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
