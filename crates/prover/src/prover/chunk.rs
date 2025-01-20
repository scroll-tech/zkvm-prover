use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::{Sdk, StdIn, config::SdkVmConfig};

#[cfg(feature = "scroll")]
use sbv::{
    core::ChunkInfo,
    primitives::{BlockWithSenders, BlockWitness},
};

use crate::{
    ChunkProof, Error, Prover, ProverVerifier, WrappedProof, proof::ChunkProofMetadata,
    task::chunk::ChunkProvingTask,
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

    fn setup<P: AsRef<Path>>(path_exe: P, path_pk: P, cache_dir: Option<P>) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(path_exe, path_pk)?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            outermost_data: None,
            cache_dir: cache_dir.map(|path| PathBuf::from(path.as_ref())),
        })
    }

    fn metadata(_task: &Self::ProvingTask) -> Result<Self::ProofMetadata, Error> {
        #[cfg(feature = "scroll")]
        let chunk_info = {
            let chain_id = _task.block_witnesses[0].chain_id;
            let pre_state_root = _task.block_witnesses[0].pre_state_root;
            let blocks = _task
                .block_witnesses
                .iter()
                .map(|s| s.build_reth_block())
                .collect::<Result<Vec<BlockWithSenders>, _>>()
                .map_err(|e| Error::GenProof(e.to_string()))?;
            ChunkInfo::from_blocks_iter(chain_id, pre_state_root, blocks.iter().map(|b| &b.block))
        };
        Ok(ChunkProofMetadata {
            #[cfg(feature = "scroll")]
            chunk_info,
        })
    }

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

        let proof = Sdk
            .generate_root_proof(
                Arc::clone(&self.app_pk),
                Arc::clone(&self.app_committed_exe),
                agg_stark_pk.clone(),
                stdin,
            )
            .map_err(|e| Error::GenProof(e.to_string()))?;

        let metadata = Self::metadata(task)?;
        let wrapped_proof = WrappedProof::new(metadata, proof);

        Ok(wrapped_proof)
    }

    fn verify_proof(&self, proof: Self::Proof) -> Result<(), Error> {
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
