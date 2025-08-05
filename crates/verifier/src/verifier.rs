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

use crate::commitments::{batch, bundle, chunk};

/// Proving key for STARK aggregation. Primarily used to aggregate
/// [continuation proofs][openvm_sdk::prover::vm::ContinuationVmProof].
static AGG_STARK_PROVING_KEY: Lazy<AggStarkProvingKey> =
    Lazy::new(|| AggStarkProvingKey::keygen(AggStarkConfig::default()).unwrap());

pub struct UniversalVerifier {
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: Vec<u8>,
}

impl UniversalVerifier {
    pub fn setup<P: AsRef<Path>>(
        path_root_committed_exe: P,
        path_verifier_code: P,
    ) -> eyre::Result<Self> {
        let root_committed_exe = std::fs::read(path_root_committed_exe.as_ref())
            .map_err(|e| e.into())
            .and_then(|bytes| bincode_v1::deserialize(&bytes))?;

        let evm_verifier = std::fs::read(path_verifier_code.as_ref())?;

        Ok(Self {
            root_committed_exe,
            evm_verifier,
        })
    }

    pub fn verify_proof(&self, root_proof: &StarkProof, vk: &[u8]) -> eyre::Result<()> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        verify_stark_proof(root_proof, prog_commit.exe, prog_commit.leaf).expect("fixme");

        Ok(())
    }

    pub fn verify_proof_evm(&self, evm_proof: &OpenVmEvmProof, vk: &[u8]) -> eyre::Result<bool> {
        let prog_commit = ProgramCommitment::deserialize(vk);

        if evm_proof.app_commit.app_exe_commit.to_u32_digest() != prog_commit.exe {
            eyre::bail!("evm: mismatch EXE commitment");
        }
        if evm_proof.app_commit.app_vm_commit.to_u32_digest() != prog_commit.leaf {
            eyre::bail!("evm: mismatch LEAF commitment");
        }

        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof)
            .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

        Ok(true)
    }
}

/// Verify a stark proof.
pub fn verify_stark_proof(
    root_proof: &StarkProof,
    exe_commit: [u32; 8],
    vm_commit: [u32; 8],
) -> Result<(), String> {
    let agg_stark_pk = &AGG_STARK_PROVING_KEY;
    let sdk = Sdk::new();
    sdk.verify_e2e_stark_proof(
        agg_stark_pk,
        root_proof,
        &CommitBytes::from_u32_digest(&exe_commit).to_bn254(),
        &CommitBytes::from_u32_digest(&vm_commit).to_bn254(),
    )
    .unwrap();
    Ok(())
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
        pub fn verify_wrapped_proof(&self, proof: &WrappedProof) -> eyre::Result<bool> {
            match &proof.proof {
                ProofEnum::Evm(p) => {
                    crate::evm::verify_evm_proof(&self.evm_verifier, &p.clone().into())
                        .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;
                    Ok(true)
                }
                ProofEnum::Root(p) => self.verify_proof(p, &proof.vk),
            }
        }

        /// test method to be compatible with euclid wrapped proofs
        pub fn verify_proof_enum(&self, proof: &ProofEnum) -> eyre::Result<bool> {
            match &proof {
                ProofEnum::Evm(p) => {
                    let evm_proof: RawEvmProof = p.clone().into();
                    crate::evm::verify_evm_proof(&self.evm_verifier, &evm_proof)
                        .map_err(|e| eyre::eyre!("evm execute fail {e}"))?;

                    println!(
                        "verified evm proof, digest_1: {:#?}; digest_2: {:#?}",
                        evm_proof.instances[12], evm_proof.instances[13]
                    );
                }
                ProofEnum::Root(p) => {
                    let inst = self.verify_proof_inner(p)?;
                    let inst: Vec<u32> = inst.into_iter().map(|v| v.unwrap()).collect();
                    let expected_vk = ProgramCommitment {
                        exe: inst.as_slice()[..8].try_into()?,
                        leaf: inst.as_slice()[8..16].try_into()?,
                    };
                    use base64::{Engine, prelude::BASE64_STANDARD};
                    println!(
                        "verified proof, expcted vk: {}",
                        BASE64_STANDARD.encode(expected_vk.serialize())
                    );
                }
            }
            Ok(true)
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
        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        verifier.verify_proof_enum(&evm_proof)?;
        verifier.verify_proof_enum(&chunk_proof)?;
        verifier.verify_proof_enum(&batch_proof)?;

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

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&chunk_proof.vk);
        let root_proof = chunk_proof.proof.as_stark_proof().unwrap();
        verify_stark_proof(root_proof, commitment.exe, commitment.leaf).unwrap();
        assert!(
            verifier.verify_proof(root_proof, &chunk_proof.vk)?,
            "proof verification failed",
        );

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

        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&batch_proof.vk);
        let root_proof = batch_proof.proof.as_stark_proof().unwrap();
        verify_stark_proof(root_proof, commitment.exe, commitment.leaf).unwrap();

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

        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        assert!(verifier.verify_proof_evm(
            &evm_proof.proof.into_evm_proof().unwrap().into(),
            &evm_proof.vk
        )?);

        Ok(())
    }
}
