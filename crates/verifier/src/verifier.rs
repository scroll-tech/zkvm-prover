use once_cell::sync::Lazy;
use std::{marker::PhantomData, path::Path};

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

pub trait VerifierType {
    const EXE_COMMIT: [u32; 8];
    const VM_COMMIT: [u32; 8];
    fn get_app_vk() -> Vec<u8> {
        ProgramCommitment {
            exe: Self::EXE_COMMIT,
            leaf: Self::VM_COMMIT,
        }
        .serialize()
    }
}

pub struct ChunkVerifierType;
pub struct BatchVerifierType;
pub struct BundleVerifierType;

impl VerifierType for ChunkVerifierType {
    const EXE_COMMIT: [u32; 8] = chunk::EXE_COMMIT;
    const VM_COMMIT: [u32; 8] = chunk::VM_COMMIT;
}

impl VerifierType for BatchVerifierType {
    const EXE_COMMIT: [u32; 8] = batch::EXE_COMMIT;
    const VM_COMMIT: [u32; 8] = batch::VM_COMMIT;
}
impl VerifierType for BundleVerifierType {
    const EXE_COMMIT: [u32; 8] = bundle::EXE_COMMIT;
    const VM_COMMIT: [u32; 8] = bundle::VM_COMMIT;
}

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

pub struct Verifier<Type> {
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: Vec<u8>,

    _type: PhantomData<Type>,
}

pub type AnyVerifier = Verifier<ChunkVerifierType>;
pub type ChunkVerifier = Verifier<ChunkVerifierType>;
pub type BatchVerifier = Verifier<BatchVerifierType>;
pub type BundleVerifier = Verifier<BundleVerifierType>;

impl<Type> Verifier<Type> {
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
            _type: PhantomData,
        })
    }

    pub fn switch_to<AnotherType>(self) -> Verifier<AnotherType> {
        Verifier::<AnotherType> {
            root_committed_exe: self.root_committed_exe,
            evm_verifier: self.evm_verifier,
            _type: PhantomData,
        }
    }

    pub fn to_chunk_verifier(self) -> ChunkVerifier {
        self.switch_to()
    }
    pub fn to_batch_verifier(self) -> BatchVerifier {
        self.switch_to()
    }
    pub fn to_bundle_verifier(self) -> BundleVerifier {
        self.switch_to()
    }
}

impl<Type: VerifierType> Verifier<Type> {
    pub fn get_app_vk(&self) -> Vec<u8> {
        Type::get_app_vk()
    }

    pub fn verify_proof(&self, root_proof: &StarkProof) -> bool {
        verify_stark_proof(root_proof, Type::EXE_COMMIT, Type::VM_COMMIT).is_ok()
    }

    pub fn verify_evm_proof(&self, evm_proof: &OpenVmEvmProof) -> bool {
        assert_eq!(
            evm_proof.app_commit.app_exe_commit.to_u32_digest(),
            Type::EXE_COMMIT,
            "mismatch EXE commitment"
        );
        assert_eq!(
            evm_proof.app_commit.app_vm_commit.to_u32_digest(),
            Type::VM_COMMIT,
            "mismatch LEAF commitment"
        );
        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof).is_ok()
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
    use std::path::Path;

    use scroll_zkvm_prover::{
        AsStarkProof, BatchProof, BundleProof, ChunkProof, IntoEvmProof, PersistableProof,
    };
    use scroll_zkvm_types::types_agg::ProgramCommitment;

    use super::*;

    const PATH_TESTDATA: &str = "./testdata";

    #[ignore = "need release assets"]
    #[test]
    fn verify_universal_proof() -> eyre::Result<()> {
        let chunk_proof = ChunkProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;
        let batch_proof = BatchProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;
        let evm_proof = BundleProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = UniversalVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        verifier.verify_proof(
            chunk_proof.as_stark_proof(),
            &ChunkVerifierType::get_app_vk(),
        )?;
        verifier.verify_proof(
            batch_proof.as_stark_proof(),
            &BatchVerifierType::get_app_vk(),
        )?;
        verifier.verify_proof_evm(
            &evm_proof.into_evm_proof(),
            &BundleVerifierType::get_app_vk(),
        )?;

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_chunk_proof() -> eyre::Result<()> {
        let chunk_proof = ChunkProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("chunk-proof-phase2.json"),
        )?;

        // Note: the committed exe has to match the version of openvm
        // which is used to generate the proof
        let verifier = ChunkVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&chunk_proof.vk);
        let root_proof = chunk_proof.as_stark_proof();
        verify_stark_proof(root_proof, commitment.exe, commitment.leaf).unwrap();
        assert!(
            verifier.verify_proof(root_proof),
            "proof verification failed",
        );

        Ok(())
    }

    #[ignore = "need release assets"]
    #[test]
    fn verify_batch_proof() -> eyre::Result<()> {
        let batch_proof = BatchProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("batch-proof-phase2.json"),
        )?;

        let _verifier = BatchVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        let commitment = ProgramCommitment::deserialize(&batch_proof.vk);
        let root_proof = batch_proof.as_stark_proof();
        verify_stark_proof(root_proof, commitment.exe, commitment.leaf).unwrap();

        Ok(())
    }

    #[ignore = "need released assets"]
    #[test]
    fn verify_bundle_proof() -> eyre::Result<()> {
        let evm_proof = BundleProof::from_json(
            Path::new(PATH_TESTDATA)
                .join("proofs")
                .join("bundle-proof-phase2.json"),
        )?;

        let verifier = BundleVerifier::setup(
            Path::new(PATH_TESTDATA).join("root-verifier-committed-exe"),
            Path::new(PATH_TESTDATA).join("verifier.bin"),
        )?;

        assert!(verifier.verify_evm_proof(&evm_proof.into_evm_proof()));

        Ok(())
    }
}
