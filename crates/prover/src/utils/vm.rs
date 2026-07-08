use openvm_sdk::{Sdk, SdkError, StdIn, types::ExecutableFormat};

pub struct ExecutionResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<u8>,
}

// the 100* current cost / ratio for chunk circuit, use to estimated the max cycles
// which an metered execution can handle
const COST_CYCLE_RATIO: u64 = 87u64;

// Execute the guest program using the metered executor first to measure actual cycles.
// If the execution exceeds the maximum cost allowed by the metered executor,
// we re-execute the program using the normal executor (execute_e1), which has no limitations
// on the size of the execution process.
pub fn execute_guest(
    sdk: &Sdk,
    exe: impl Into<ExecutableFormat>,
    inputs: &StdIn,
) -> Result<ExecutionResult, SdkError> {
    let exe = sdk.convert_to_exe(exe)?;
    let mut compiled = sdk.compile_metered_cost(exe.clone())?;
    let preset_max_cost = compiled.ctx.max_execution_cost * 2;
    let estimated_max_cycles = preset_max_cost / COST_CYCLE_RATIO;
    tracing::info!("Double preset max cost to ({preset_max_cost}) for metering execution");
    compiled.ctx = compiled.ctx.with_max_execution_cost(preset_max_cost);
    let (mut public_values, (cost, instret)) =
        sdk.execute_metered_cost(&compiled, inputs.clone())?;
    let mut total_cycle = instret;

    if public_values.iter().all(|x| *x == 0) {
        if cost < compiled.ctx.max_execution_cost {
            return Err(SdkError::Other(eyre::eyre!(
                "public_values are all 0s for unexpected reason"
            )));
        }

        tracing::warn!(
            "Large execution exceed limit of metered execution, cycle is expected to >{estimated_max_cycles}"
        );
        let compiled_pure = sdk.compile(exe)?;
        public_values = sdk.execute(&compiled_pure, inputs.clone())?;
        total_cycle = estimated_max_cycles;

        if public_values.iter().all(|x| *x == 0) {
            return Err(SdkError::Other(eyre::eyre!(
                "public_values are all 0s upon execute_e1"
            )));
        }
    }

    tracing::debug!(name: "public_values after guest execution: {:?}", ?public_values);
    Ok(ExecutionResult {
        total_cycle,
        public_values,
    })
}
