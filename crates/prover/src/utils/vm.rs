use std::sync::Arc;

use openvm_circuit::{
    arch::{ExecutionSegment, GenerationError, VmExecutor, instructions::exe::VmExe},
    system::{memory::tree::public_values::extract_public_values, program::trace::VmCommittedExe},
};
use openvm_sdk::{F, SC, StdIn, config::SdkVmConfig};
use openvm_stark_sdk::{
    config::{FriParameters, baby_bear_poseidon2::BabyBearPoseidon2Engine},
    engine::StarkFriEngine,
};

use crate::Error;

pub struct ExecutionResult {
    pub total_cycle: u64,
    pub total_tick: u64,
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
    use openvm_circuit::arch::VmConfig;
    use openvm_stark_sdk::openvm_stark_backend::p3_field::Field;

    let vm = VmExecutor::new(vm_config.clone());

    let mut total_cycle: u64 = 0;
    let mut total_tick: u64 = 0;
    let mut final_memory = None;
    let segment_output: Vec<_> = vm
        .execute_and_then(
            exe,
            stdin.clone(),
            |idx: usize, segment: ExecutionSegment<_, _>| -> Result<(), GenerationError> {
                total_cycle += segment.metrics.cycle_count as u64;
                total_tick += segment.chip_complex.memory_controller().timestamp() as u64;
                tracing::debug!(
                    "after segment {idx}: cycle count: {}, tick count: {}",
                    total_cycle,
                    total_tick
                );
                final_memory = segment.final_memory.clone();
                Ok(())
            },
            |e| {
                println!("execution error: {:?}", e);
                GenerationError::Execution(e)
            },
        )
        .map_err(|e| Error::GenProof(e.to_string()))?;

    let segment_len = segment_output.len();
    tracing::info!("segment length" = ?segment_len);
    tracing::info!("total cycle" = ?total_cycle);
    tracing::info!("final ts" = ?total_tick);

    let system_config = <SdkVmConfig as VmConfig<F>>::system(&vm_config);
    let public_values: Vec<F> = extract_public_values(
        &system_config.memory_config.memory_dimensions(),
        system_config.num_public_values,
        final_memory.as_ref().unwrap(),
    );
    tracing::debug!(name: "public_values after guest execution", ?public_values);
    if public_values.iter().all(|x| x.is_zero()) {
        return Err(Error::GenProof("public_values are all 0s".to_string()));
    }

    Ok(ExecutionResult {
        total_cycle,
        total_tick,
        public_values,
    })
}
