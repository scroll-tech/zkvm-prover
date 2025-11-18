use openvm_sdk::{Sdk, StdIn, types::ExecutableFormat};

use crate::Error;

pub struct ExecutionResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<u8>,
}

pub fn execute_guest(
    sdk: &Sdk,
    exe: impl Into<ExecutableFormat>,
    stdin: &StdIn,
) -> Result<ExecutionResult, Error> {
    let (public_values, (_cost, total_cycle)) = sdk
        .execute_metered_cost(exe, stdin.clone())
        .map_err(|e| Error::GenProof(e.to_string()))?;

    tracing::debug!(name: "public_values after guest execution", ?public_values);
    if public_values.iter().all(|x| *x == 0) {
        return Err(Error::GenProof("public_values are all 0s".to_string()));
    }

    Ok(ExecutionResult {
        total_cycle,
        public_values,
    })
}
