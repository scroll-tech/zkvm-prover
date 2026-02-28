use openvm_circuit::{
    arch::{SystemConfig, VirtualMachineError},
    system::memory::merkle::public_values::extract_public_values,
};
use openvm_sdk::{Sdk, SdkError, StdIn, types::ExecutableFormat};

pub struct ExecutionResult {
    pub total_cycle: u64,
    #[allow(dead_code)]
    pub public_values: Vec<u8>,
}

pub fn execute_guest(
    sdk: &Sdk,
    sys_config: &SystemConfig,
    exe: impl Into<ExecutableFormat>,
    inputs: &StdIn,
) -> Result<ExecutionResult, SdkError> {
    let app_prover = sdk.app_prover(exe)?;

    let vm = app_prover.vm();
    let exe = app_prover.exe();

    let ctx = vm.build_metered_cost_ctx();
    let preset_max_cost = ctx.max_execution_cost;
    tracing::info!("Double preset max cost ({preset_max_cost}) for metering execution");
    let ctx = ctx.with_max_execution_cost(preset_max_cost * 2);
    let interpreter = vm
        .metered_cost_interpreter(&exe)
        .map_err(VirtualMachineError::from)?;

    let (ctx, final_state) = interpreter
        .execute_metered_cost(inputs.clone(), ctx)
        .map_err(VirtualMachineError::from)?;
    let mut total_cycle = ctx.instret;

    let mut public_values =
        extract_public_values(sys_config.num_public_values, &final_state.memory.memory);

    if public_values.iter().all(|x| *x == 0) {
        if ctx.cost < ctx.max_execution_cost {
            return Err(SdkError::Other(eyre::eyre!(
                "public_values are all 0s for unexpected reason"
            )));
        }

        tracing::warn!(
            "Large execution exceed limit of metered execution, cycle is expected to >2.4B"
        );
        let exe = sdk.convert_to_exe(exe)?;
        let instance = vm.interpreter(&exe).map_err(VirtualMachineError::from)?;
        let final_memory = instance
            .execute(inputs.clone(), None)
            .map_err(VirtualMachineError::from)?
            .memory;
        public_values = extract_public_values(sys_config.num_public_values, &final_memory.memory);
        total_cycle = 2_400_000_000_u64;

        // there should be no other reason to get PI with all 0
        assert!(!public_values.iter().all(|x| *x == 0));
    }

    tracing::debug!(name: "public_values after guest execution: {:?}", ?public_values);
    Ok(ExecutionResult {
        total_cycle,
        public_values,
    })
}
