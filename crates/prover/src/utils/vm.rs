use std::sync::Arc;

use openvm_circuit::{
    arch::{instructions::exe::VmExe, GenerationError, VmExecutor, VmSegmentExecutor},
    system::{memory::merkle::public_values::extract_public_values, program::trace::VmCommittedExe},
};
use openvm_sdk::{F, SC, StdIn, config::SdkVmConfig};
use openvm_stark_sdk::{
    config::{FriParameters, baby_bear_poseidon2::BabyBearPoseidon2Engine},
    engine::StarkFriEngine,
};

use crate::Error;

pub struct ExecutionResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<F>,
}

#[derive(Default)]
pub struct DebugInput {
    pub mock_prove: bool,
    pub commited_exe: Option<Arc<VmCommittedExe<SC>>>,
}

pub fn execute_guest(
    vm_config: SdkVmConfig,
    exe: VmExe<F>,
    stdin: &StdIn,
) -> Result<ExecutionResult, Error> {
    use openvm_stark_sdk::openvm_stark_backend::p3_field::Field;

    let vm = VmExecutor::new(vm_config.clone()).unwrap();

    let state = vm.execute_e1(exe, stdin.clone(), None).unwrap();
    let final_memory = state.memory;
    let total_cycle = state.instret;
        
    let public_values: Vec<F> = extract_public_values(
        vm_config.as_ref().num_public_values,
        &final_memory.memory,
    );
    tracing::debug!(name: "public_values after guest execution", ?public_values);
    if public_values.iter().all(|x| x.is_zero()) {
        return Err(Error::GenProof("public_values are all 0s".to_string()));
    }

    Ok(ExecutionResult {
        total_cycle,
        public_values,
    })
}
