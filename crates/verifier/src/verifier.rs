use once_cell::sync::Lazy;
use openvm_sdk::commit::AppExecutionCommit;
use openvm_sdk::keygen::{AggProvingKey, AggVerifyingKey};
use openvm_sdk::{Sdk, commit::CommitBytes};
use scroll_zkvm_types::proof::OpenVmEvmProof;
use scroll_zkvm_types::{proof::StarkProof, utils::serialize_vk};
use std::path::Path;

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
pub static AGG_STARK_PROVING_KEY: Lazy<AggProvingKey> =
    Lazy::new(|| Sdk::riscv32().agg_pk().clone());

pub struct UniversalVerifier {
    pub evm_verifier: Vec<u8>,
    pub loaded_agg_vk: AggVerifyingKey,
}

impl UniversalVerifier {
    pub fn verify_stark_proof_with_vk(
        agg_stark_vk: &AggVerifyingKey,
        stark_proof: &StarkProof,
        vk: &[u8],
    ) -> eyre::Result<()> {
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
        Sdk::verify_proof(agg_stark_vk, expected_app_commit, &vm_stark_proof)?;

        Ok(())
    }

    pub fn setup<P: AsRef<Path>>(path_verifier: P) -> eyre::Result<Self> {
        let path_verifier_code = path_verifier.as_ref().join("verifier.bin");
        let path_agg_vk = path_verifier.as_ref().join("root_verifier_vk");
        let evm_verifier = std::fs::read(path_verifier_code)?;
        let loaded_agg_vk = openvm_sdk::fs::read_object_from_file(path_agg_vk).unwrap_or_else(
            |_|{
                tracing::warn!("root_Verifier_vk is not avaliable in disk, try to calculate it on-the-fly, which may be time consuming ...");
                AGG_STARK_PROVING_KEY.get_agg_vk()
            }
        );

        Ok(Self {
            evm_verifier,
            loaded_agg_vk,
        })
    }

    pub fn verify_stark_proof(&self, stark_proof: &StarkProof, vk: &[u8]) -> eyre::Result<()> {
        Self::verify_stark_proof_with_vk(&self.loaded_agg_vk, stark_proof, vk)
    }

    pub fn verify_evm_proof(&self, evm_proof: &OpenVmEvmProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = serialize_vk::deserialize(vk);

        if evm_proof.app_commit.app_exe_commit.to_u32_digest() != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.app_commit.app_vm_commit.to_u32_digest() != prog_commit.vm {
            eyre::bail!("evm: mismatch VM commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof)
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
                ProofEnum::Stark(p) => self.verify_stark_proof(p, &proof.vk),
            }
        }
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-feynman.json"),
        )?;
        let verifier = UniversalVerifier::setup(Path::new(PATH_TESTDATA))?;

        let stark_proof = chunk_proof.proof.as_stark_proof().unwrap();
        verifier.verify_stark_proof(stark_proof, &chunk_proof.vk)?;

        Ok(())
    }

    #[ignore = "need euclid released assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = WrappedProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-feynman.json"),
        )?;
        let verifier = UniversalVerifier::setup(Path::new(PATH_TESTDATA))?;

        let stark_proof = batch_proof.proof.as_stark_proof().unwrap();
        verifier.verify_stark_proof(stark_proof, &batch_proof.vk)?;

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

        let verifier = UniversalVerifier::setup(Path::new(PATH_TESTDATA))?;

        verifier.verify_evm_proof(
            &evm_proof.proof.into_evm_proof().unwrap().into(),
            &evm_proof.vk,
        )?;

        Ok(())
    }
}
