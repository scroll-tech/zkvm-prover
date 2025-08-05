use once_cell::sync::Lazy;
use std::path::Path;

use openvm_circuit::system::program::trace::VmCommittedExe;
use openvm_sdk::{
    F, RootSC, SC, Sdk,
    commit::{AppExecutionCommit, CommitBytes},
    config::AggStarkConfig,
    keygen::AggStarkProvingKey,
    types::EvmProof,
};
use scroll_zkvm_types::proof::OpenVmEvmProof;
use scroll_zkvm_types::{
    proof::StarkProof,
    types_agg::{AggregationInput, ProgramCommitment},
};
use tracing::{debug, instrument};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()).unwrap());

pub struct UniversalVerifier {
    pub evm_verifier: Vec<u8>,
}

impl UniversalVerifier {
    pub fn setup<P: AsRef<Path>>(path_verifier_code: P) -> eyre::Result<Self> {
        let evm_verifier = std::fs::read(path_verifier_code.as_ref())?;

        Ok(Self { evm_verifier })
    }

    pub fn verify_stark_proof(stark_proof: &StarkProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        if stark_proof.exe_commitment != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if stark_proof.vm_commitment != prog_commit.leaf {
            eyre::bail!("evm: mismatch LEAF commitment");
        }

        let agg_stark_pk = &AGG_STARK_PROVING_KEY;
        let sdk = Sdk::new();

        use openvm_continuations::verifier::internal::types::VmStarkProof;
        let vm_stark_proof = VmStarkProof {
            proof: stark_proof.proof.clone(),
            user_public_values: stark_proof.user_public_values.clone(),
        };
        sdk.verify_e2e_stark_proof(
            agg_stark_pk,
            &vm_stark_proof,
            &CommitBytes::from_u32_digest(&prog_commit.exe).to_bn254(),
            &CommitBytes::from_u32_digest(&prog_commit.leaf).to_bn254(),
        )
        .unwrap();

        Ok(())
    }

    pub fn verify_evm_proof(&self, evm_proof: &OpenVmEvmProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        if evm_proof.app_commit.app_exe_commit.to_u32_digest() != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.app_commit.app_vm_commit.to_u32_digest() != prog_commit.leaf {
            eyre::bail!("evm: mismatch LEAF commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof)
            .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test::WrappedProof;
    use scroll_zkvm_prover::utils::read_json;
    use scroll_zkvm_types::{proof::ProofEnum, types_agg::ProgramCommitment};
    use std::path::Path;

    use super::*;

    const PATH_TESTDATA: &str = "./testdata";

    impl UniversalVerifier {
        /// test method to be compatible with euclid wrapped proofs
        pub fn verify_wrapped_proof(&self, proof: &WrappedProof) -> eyre::Result<()> {
            match &proof.proof {
                ProofEnum::Evm(p) => self.verify_evm_proof(&p.clone().into(), &proof.vk),
                ProofEnum::Stark(p) => Self::verify_stark_proof(p, &proof.vk),
            }
        }
    }

    #[ignore = "need released assets"]
    #[test]
    fn verify_universal_proof() -> eyre::Result<()> {
        let chunk_proof: ProofEnum = read_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-feynman.json"),
        )?;
        let batch_proof: ProofEnum = read_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-feynman.json"),
        )?;
        let evm_proof: ProofEnum = read_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-feynman.json"),
        )?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = UniversalVerifier::setup(Path::new(PATH_TESTDATA).join("verifier.bin"))?;

        let evm_proof = evm_proof.as_evm_proof().unwrap();
        // TODO: we need vk to verify a proof.
        //verifier.verify_evm_proof(&evm_proof, evm_proof)?;
        //verifier.verify_proof_enum(&chunk_proof)?;
        //verifier.verify_proof_enum(&batch_proof)?;

        Ok(())
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;

        let root_proof = chunk_proof.proof.as_stark_proof().unwrap();
        UniversalVerifier::verify_stark_proof(root_proof, &chunk_proof.vk)?;

        Ok(())
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;

        let root_proof = batch_proof.proof.as_stark_proof().unwrap();
        UniversalVerifier::verify_stark_proof(root_proof, &batch_proof.vk).unwrap();

        Ok(())
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_bundle_proof() -> eyre::Result<()> {
        let evm_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        let verifier = UniversalVerifier::setup(Path::new(PATH_TESTDATA).join("verifier.bin"))?;

        verifier.verify_evm_proof(
            &evm_proof.proof.into_evm_proof().unwrap().into(),
            &evm_proof.vk,
        )?;

        Ok(())
    }
}
