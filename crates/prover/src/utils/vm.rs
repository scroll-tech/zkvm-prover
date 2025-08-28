use std::sync::Arc;

use openvm_circuit::{
    arch::{VmExecutor, instructions::exe::VmExe},
    system::{
        memory::merkle::public_values::extract_public_values, program::trace::VmCommittedExe,
    },
};
use openvm_sdk::{F, SC, StdIn, config::SdkVmConfig};

use crate::Error;

pub struct ExecutionResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<u8>,
}

#[derive(Default)]
pub struct DebugInput {
    pub mock_prove: bool,
    pub commited_exe: Option<Arc<VmCommittedExe<SC>>>,
}

pub fn execute_guest(
    vm_config: SdkVmConfig,
    exe: &VmExe<F>,
    stdin: &StdIn,
) -> Result<ExecutionResult, Error> {
    let executor = VmExecutor::new(vm_config.clone()).expect("invalid config");
    let instance = executor.instance(exe).expect("invalid exe");

    let state = instance
        .execute(stdin.clone(), None)
        .map_err(|e| Error::GenProof(e.to_string()))?;
    let final_memory = state.memory;
    let total_cycle = state.instret;

    let public_values: Vec<u8> =
        extract_public_values(vm_config.as_ref().num_public_values, &final_memory.memory);
    tracing::debug!(name: "public_values after guest execution", ?public_values);
    if public_values.iter().all(|x| *x == 0) {
        return Err(Error::GenProof("public_values are all 0s".to_string()));
    }

    Ok(ExecutionResult {
        total_cycle,
        public_values,
    })
}
