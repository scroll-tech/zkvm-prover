use std::{marker::PhantomData, path::Path};

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{
    halo2::{EvmProof, wrapper::EvmVerifier},
    hints::Hintable,
};
use openvm_sdk::{
    F, RootSC, SC, verifier::root::types::RootVmVerifierInput,
    config::AggStarkConfig, keygen::AggStarkProvingKey,
};
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
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
    pub evm_verifier: Option<EvmVerifier>,

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
            Some(EvmVerifier(verifier_code))
        };

        Ok(Self {
            vm_executor,
            root_committed_exe,
            evm_verifier,
            _type: PhantomData,
        })
    }

    pub fn root_verifier<P: AsRef<Path>>(
        path_vm_config: P,
    ) -> eyre::Result<Self> {
        let vm_executor = {
            let bytes = std::fs::read(path_vm_config.as_ref())?;
            let vm_config: NativeConfig = bincode::deserialize(&bytes)?;
            SingleSegmentVmExecutor::new(vm_config)
        };

        let (agg_stark_pk, _) = AggStarkProvingKey::dummy_proof_and_keygen(AggStarkConfig::default());

        let root_committed_exe = agg_stark_pk.root_verifier_pk.root_committed_exe.as_ref().clone();

        Ok(Self {
            vm_executor,
            root_committed_exe,
            evm_verifier: None,
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

    pub fn verify_proof_with_pi(&self, root_proof: &RootVmVerifierInput<SC>) -> eyre::Result<Vec<Option<u32>>> {
        let ret = self.vm_executor
            .execute_and_compute_heights(self.root_committed_exe.exe.clone(), root_proof.write())
            .map(|r|{
                println!("proof contain {} PIs", r.public_values.len());
                r.public_values.iter().map(|op_f|op_f.map(|f|f.as_canonical_u32())).collect::<Vec<_>>()
            })?;
        Ok(ret)
    }

    pub fn verify_proof_evm(&self, evm_proof: &EvmProof) -> bool {
        crate::evm::verify_evm_proof(self.evm_verifier.as_ref().expect("must created evm verifier"), evm_proof).is_ok()
    }
}
