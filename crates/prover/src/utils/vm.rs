use openvm_sdk::{Sdk, SdkError, StdIn, types::ExecutableFormat};
use openvm_circuit::{
    arch::{VirtualMachineError, SystemConfig},
    system::memory::merkle::public_values::extract_public_values,
};

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
) -> Result<ExecutionResult, SdkError>{

    let app_prover = sdk.app_prover(exe)?;

    let vm = app_prover.vm();
    let exe = app_prover.exe();

    let ctx = vm.build_metered_cost_ctx();
    let interpreter = vm
        .metered_cost_interpreter(&exe)
        .map_err(VirtualMachineError::from)?;

    let (ctx, final_state) = interpreter
        .execute_metered_cost(inputs.clone(), ctx)
        .map_err(VirtualMachineError::from)?;
    let mut total_cycle = ctx.instret;

    let mut public_values = extract_public_values(
        sys_config.num_public_values,
        &final_state.memory.memory,
    );

    if public_values.iter().all(|x| *x == 0) {
        tracing::warn!("Large execution exceed limit of metered execution, cycle is expected to >1.2B");
        let exe = sdk.convert_to_exe(exe)?;
        let instance = vm.interpreter(&exe)
            .map_err(VirtualMachineError::from)?;
        let final_memory = instance
            .execute(inputs.clone(), None)
            .map_err(VirtualMachineError::from)?
            .memory;
        public_values = extract_public_values(
            sys_config.num_public_values,
            &final_memory.memory,
        );
        total_cycle = 1_200_000_000_u64;
    }

    Ok(ExecutionResult {
        total_cycle,
        public_values,
    })

}
