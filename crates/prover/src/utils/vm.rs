use openvm_circuit::{
    arch::{ExecutionSegment, VmExecutor, instructions::exe::VmExe},
    system::memory::tree::public_values::extract_public_values,
};
use openvm_sdk::{F, StdIn, config::SdkVmConfig};

use crate::Error;

pub struct ExecResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<F>,
    pub segments: Vec<ExecutionSegment<F, SdkVmConfig>>,
}

pub fn execute_exe(config: SdkVmConfig, exe: VmExe<F>, stdin: &StdIn) -> Result<ExecResult, Error> {
    use openvm_circuit::arch::VmConfig;
    use openvm_stark_sdk::openvm_stark_backend::p3_field::Field;

    let vm = VmExecutor::new(config.clone());

    let segments = vm
        .execute_segments(exe, stdin.clone())
        .map_err(|e| Error::GenProof(e.to_string()))?;
    let total_cycle = segments
        .iter()
        .map(|seg| seg.metrics.cycle_count)
        .sum::<usize>() as u64;
    tracing::info!(name: "segment length", segment_len = segments.len());
    tracing::info!(name: "total cycle", ?total_cycle);

    // extract and check public values
    let final_memory = segments
        .last()
        .and_then(|x| x.final_memory.as_ref())
        .unwrap();
    let system_config = <SdkVmConfig as VmConfig<F>>::system(&config);
    let public_values: Vec<F> = extract_public_values(
        &system_config.memory_config.memory_dimensions(),
        system_config.num_public_values,
        final_memory,
    );
    tracing::debug!(name: "public_values after guest execution", ?public_values);
    if public_values.iter().all(|x| x.is_zero()) {
        return Err(Error::GenProof("public_values are all 0s".to_string()));
    }
    Ok(ExecResult {
        total_cycle,
        public_values,
        segments,
    })
}
