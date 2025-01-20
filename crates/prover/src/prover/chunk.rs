use std::{path::Path, sync::Arc};

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::{Sdk, StdIn, config::SdkVmConfig, verifier::root::types::RootVmVerifierInput};

use crate::{Error, Prover, ProverVerifier, prover::SC};

use super::AGG_STARK_PROVING_KEY;

/// Prover for [`ChunkCircuit`].
pub type ChunkProver = Prover<SdkVmConfig>;

/// Alias for convenience.
type AggregationProof = RootVmVerifierInput<SC>;

impl ProverVerifier for ChunkProver {
    type Witness = Vec<sbv::primitives::types::BlockWitness>;

    type Proof = AggregationProof;

    const EVM: bool = false;

    fn setup<P: AsRef<Path>>(path_exe: P, path_pk: P) -> Result<Self, Error> {
        let (app_committed_exe, app_pk) = Self::init(path_exe, path_pk)?;

        Ok(Self {
            app_committed_exe,
            app_pk,
            outermost_data: None,
        })
    }

    fn gen_proof(&self, witness: &Self::Witness) -> Result<Self::Proof, Error> {
        let agg_stark_pk = AGG_STARK_PROVING_KEY
            .get()
            .ok_or(Error::GenProof(String::from(
                "agg stark pk not initialized! Prover::setup",
            )))?;

        let serialized = rkyv::to_bytes::<rkyv::rancor::Error>(witness)
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

        Ok(proof)
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
            .execute_and_compute_heights(exe.exe.clone(), proof.write())
            .map_err(|e| Error::VerifyProof(e.to_string()))?;

        Ok(())
    }
}
