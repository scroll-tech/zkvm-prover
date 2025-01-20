use std::sync::Arc;

use openvm_circuit::arch::VmConfig;
use openvm_sdk::{
    NonRootCommittedExe, Sdk, StdIn,
    keygen::{AggStarkProvingKey, AppProvingKey},
    verifier::root::types::RootVmVerifierInput,
};
use openvm_stark_sdk::{
    config::baby_bear_poseidon2::BabyBearPoseidon2Config, openvm_stark_backend::Chip,
    p3_baby_bear::BabyBear,
};

use crate::Error;

type SC = BabyBearPoseidon2Config;
type F = BabyBear;

/// Generate a [root proof][openvm_sdk::verifier::root::types::RootVmVerifierInput] for circuit.
pub fn gen_proof<VC: VmConfig<F>>(
    app_pk: Arc<AppProvingKey<VC>>,
    app_exe: Arc<NonRootCommittedExe>,
    agg_stark_pk: AggStarkProvingKey,
    inputs: StdIn,
) -> Result<RootVmVerifierInput<SC>, Error>
where
    VC::Executor: Chip<SC>,
    VC::Periphery: Chip<SC>,
{
    Sdk.generate_root_proof(app_pk, app_exe, agg_stark_pk, inputs)
        .map_err(|e| Error::GenProof(e.to_string()))
}
