use once_cell::sync::Lazy;
use openvm_sdk::commit::AppExecutionCommit;
use openvm_sdk::keygen::{AggProvingKey, AggVerifyingKey};
use openvm_sdk::{Sdk, commit::CommitBytes};
use scroll_zkvm_types::proof::OpenVmEvmProof;
use scroll_zkvm_types::{proof::StarkProof, utils::serialize_vk};
use std::path::{Path, PathBuf};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
pub static AGG_STARK_PROVING_KEY: Lazy<AggProvingKey> =
    Lazy::new(|| Sdk::riscv32().agg_pk().clone());

pub struct UniversalVerifier {
    pub evm_verifier: Option<Vec<u8>>,
    pub agg_vk: AggVerifyingKey,
}

impl UniversalVerifier {
    pub fn new() -> UniversalVerifier {
        Self::setup(None::<PathBuf>).unwrap()
    }
    pub fn setup<P: AsRef<Path>>(path_verifier_code: Option<P>) -> eyre::Result<Self> {
        tracing::info!("verifier setup");
        let evm_verifier = path_verifier_code.map(|p| std::fs::read(p.as_ref()).unwrap());

        let agg_vk = AGG_STARK_PROVING_KEY.get_agg_vk();

        tracing::info!("verifier setup done");
        Ok(Self {
            evm_verifier,
            agg_vk,
        })
    }

    pub fn verify_stark_proof(stark_proof: &StarkProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = serialize_vk::deserialize(vk);

        /*
        if stark_proof.exe_commitment != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if stark_proof.vm_commitment != prog_commit.vm {
            eyre::bail!("evm: mismatch VM commitment");
        }
        */

        use openvm_continuations::verifier::internal::types::VmStarkProof;
        let vm_stark_proof = VmStarkProof {
            inner: stark_proof.proofs[0].clone(),
            user_public_values: stark_proof.public_values.clone(),
        };
        let expected_app_commit = AppExecutionCommit {
            app_exe_commit: CommitBytes::from_u32_digest(&prog_commit.exe),
            app_vm_commit: CommitBytes::from_u32_digest(&prog_commit.vm),
        };
        Sdk::verify_proof(
            &AGG_STARK_PROVING_KEY.get_agg_vk(),
            expected_app_commit,
            &vm_stark_proof,
        )?;

        Ok(())
    }

    pub fn verify_evm_proof(&self, evm_proof: &OpenVmEvmProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = serialize_vk::deserialize(vk);

        if evm_proof.app_commit.app_exe_commit.to_u32_digest() != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.app_commit.app_vm_commit.to_u32_digest() != prog_commit.vm {
            eyre::bail!("evm: mismatch VM commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier.as_ref().unwrap(), evm_proof)
            .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::test::WrappedProof;
    use scroll_zkvm_types::proof::ProofEnum;
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

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;

        let stark_proof = chunk_proof.proof.as_stark_proof().unwrap();
        UniversalVerifier::verify_stark_proof(stark_proof, &chunk_proof.vk)?;

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

        let stark_proof = batch_proof.proof.as_stark_proof().unwrap();
        UniversalVerifier::verify_stark_proof(stark_proof, &batch_proof.vk)?;

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

        let verifier =
            UniversalVerifier::setup(Some(Path::new(PATH_TESTDATA).join("verifier.bin")))?;

        verifier.verify_evm_proof(
            &evm_proof.proof.into_evm_proof().unwrap().into(),
            &evm_proof.vk,
        )?;

        Ok(())
    }
}
