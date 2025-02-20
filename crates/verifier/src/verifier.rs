use std::path::Path;

use openvm_circuit::{arch::SingleSegmentVmExecutor, system::program::trace::VmCommittedExe};
use openvm_native_circuit::NativeConfig;
use openvm_native_recursion::{
    halo2::{EvmProof, wrapper::EvmVerifier},
    hints::Hintable,
};
use openvm_sdk::{F, RootSC, SC, verifier::root::types::RootVmVerifierInput};

pub struct Verifier {
    pub vm_executor: SingleSegmentVmExecutor<F, NativeConfig>,
    pub root_committed_exe: VmCommittedExe<RootSC>,
    pub evm_verifier: EvmVerifier,
}

impl Verifier {
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
        })
    }
}

impl Verifier {
    pub fn verify_proof(&self, root_proof: &RootVmVerifierInput<SC>) -> bool {
        self.vm_executor
            .execute_and_compute_heights(self.root_committed_exe.exe.clone(), root_proof.write())
            .is_ok()
    }

    pub fn verify_proof_evm(&self, evm_proof: &EvmProof) -> bool {
        crate::evm::verify_evm_proof(&self.evm_verifier, evm_proof).is_ok()
    }
}
