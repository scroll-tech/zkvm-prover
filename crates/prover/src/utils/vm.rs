use openvm_sdk::{Sdk, SdkError, StdIn, types::ExecutableFormat};

pub struct ExecutionResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<u8>,
}

// Execute the guest program using the metered executor first to measure actual cycles.
// If the execution exceeds the maximum cost allowed by the metered executor,
// we re-execute the program using the normal executor, which has no limitations
// on the size of the execution process.
pub fn execute_guest(
    sdk: &Sdk,
    exe: impl Into<ExecutableFormat>,
    inputs: &StdIn,
) -> Result<ExecutionResult, SdkError> {
    let exe = sdk.convert_to_exe(exe)?;
    match sdk.execute_metered_cost(exe.clone(), inputs.clone()) {
        Ok((public_values, (_cost, instret))) => {
            if public_values.iter().all(|&x| x == 0) {
                return Err(SdkError::Other(eyre::eyre!(
                    "public_values are all 0s for unexpected reason"
                )));
            }
            Ok(ExecutionResult {
                total_cycle: instret,
                public_values,
            })
        }
        Err(e) => {
            tracing::warn!("Metered execution failed: {e}, falling back to execute");
            let public_values = sdk.execute(exe, inputs.clone())?;
            if public_values.iter().all(|&x| x == 0) {
                return Err(SdkError::Other(eyre::eyre!(
                    "public_values are all 0s upon execute"
                )));
            }
            // The fallback executor does not report instruction-retired counts.
            // Use u64::MAX as a sentinel so any speed logging shows an obviously
            // invalid value instead of a misleading 0 MHz.
            Ok(ExecutionResult {
                total_cycle: u64::MAX,
                public_values,
            })
        }
    }
}
