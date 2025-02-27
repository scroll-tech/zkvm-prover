use std::{marker::PhantomData, path::Path};

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{
    halo2::{EvmProof, wrapper::EvmVerifier},
    hints::Hintable,
};
use openvm_sdk::{F, RootSC, SC, verifier::root::types::RootVmVerifierInput};
use scroll_zkvm_circuit_input_types::proof::ProgramCommitment;

use crate::commitments::{
    batch::{EXE_COMMIT as BATCH_EXE_COMMIT, LEAF_COMMIT as BATCH_LEAF_COMMIT},
    bundle::{EXE_COMMIT as BUNDLE_EXE_COMMIT, LEAF_COMMIT as BUNDLE_LEAF_COMMIT},
    chunk::{EXE_COMMIT as CHUNK_EXE_COMMIT, LEAF_COMMIT as CHUNK_LEAF_COMMIT},
};

pub trait VerifierType {
    const EXE_COMMIT: [u32; 8];
    const LEAF_COMMIT: [u32; 8];
    fn get_app_vk() -> Vec<u8> {
        ProgramCommitment {
            exe: Self::EXE_COMMIT,
            leaf: Self::LEAF_COMMIT,
        }
        .serialize()
    }
}

pub struct ChunkVerifierType;
pub struct BatchVerifierType;
pub struct BundleVerifierType;

impl VerifierType for ChunkVerifierType {
    const EXE_COMMIT: [u32; 8] = CHUNK_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = CHUNK_LEAF_COMMIT;
}
impl VerifierType for BatchVerifierType {
    const EXE_COMMIT: [u32; 8] = BATCH_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = BATCH_LEAF_COMMIT;
}
impl VerifierType for BundleVerifierType {
    const EXE_COMMIT: [u32; 8] = BUNDLE_EXE_COMMIT;
    const LEAF_COMMIT: [u32; 8] = BUNDLE_LEAF_COMMIT;
}

pub struct Verifier<Type> {
    pub vm_executor: SingleSegmentVmExecutor<F, NativeConfig>,
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: EvmVerifier,

    _type: PhantomData<Type>,
}

pub type ChunkVerifier = Verifier<ChunkVerifierType>;
pub type BatchVerifier = Verifier<BatchVerifierType>;
pub type BundleVerifier = Verifier<BundleVerifierType>;

impl<Type> Verifier<Type> {
    pub fn setup<P: AsRef<Path>>(
        path_vm_config: P,
        path_root_committed_exe: P,
        path_verifier_code: P,
    ) -> eyre::Result<Self> {
        let vm_executor = {
            let bytes = std::fs::read(path_vm_config.as_ref())?;
            let vm_config: NativeConfig = bincode::deserialize(&bytes)?;
            SingleSegmentVmExecutor::new(vm_config)
        };

        let root_committed_exe = {
            let bytes = std::fs::read(path_root_committed_exe.as_ref())?;
            bincode::deserialize(&bytes)?
        };

        let evm_verifier = {
            let verifier_code = std::fs::read(path_verifier_code.as_ref())?;
            EvmVerifier(verifier_code)
        };

        Ok(Self {
            vm_executor,
            root_committed_exe,
            evm_verifier,
            _type: PhantomData,
        })
    }
}

impl<Type: VerifierType> Verifier<Type> {
    pub fn get_app_vk(&self) -> Vec<u8> {
        Type::get_app_vk()
    }

    pub fn verify_proof(&self, root_proof: &RootVmVerifierInput<SC>) -> bool {
        self.vm_executor
            .execute_and_compute_heights(self.root_committed_exe.exe.clone(), root_proof.write())
            .is_ok()
    }

    pub fn verify_proof_evm(&self, evm_proof: &EvmProof) -> bool {
        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::ChunkVerifier;

    #[test]
    fn test_verify() -> eyre::Result<()> {
        let path_testdata = std::path::Path::new("./testdata");
        let (path_vm_config, path_root_committed_exe, path_verifier_code) = (
            path_testdata.join("root-verifier-vm-config"),
            path_testdata.join("root-verifier-committed-exe"),
            path_testdata.join("verifier.bin"),
        );
        let verifier = ChunkVerifier::setup(
            &path_vm_config,
            &path_root_committed_exe,
            &path_verifier_code,
        )?;

        macro_rules! read_proof {
            ($fd:expr, $proof_type:ident) => {{
                let path = std::path::Path::new("./testdata").join($fd);
                let proof_str = std::fs::read_to_string(&path)?;
                serde_json::from_str::<scroll_zkvm_prover::$proof_type>(&proof_str)?
            }};
        }

        let chunk_proof_1 = read_proof!("chunk-proof.json", ChunkProof);
        let chunk_proof_2 = read_proof!("chunk-proof-2.json", ChunkProof);

        let start = Instant::now();
        assert!(verifier.verify_proof(&chunk_proof_1.into_proof()));
        let duration = start.elapsed();
        println!("took {duration:?} to verify chunk-proof.json");

        let start = Instant::now();
        assert!(verifier.verify_proof(&chunk_proof_2.into_proof()));
        let duration = start.elapsed();
        println!("took {duration:?} to verify chunk-proof-2.json");

        Ok(())
    }
}
