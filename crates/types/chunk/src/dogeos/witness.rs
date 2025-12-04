use bridge_adapters_zk::serde::SerdeWrapper;
use bridge_adapters_zk::StepInputEnvelope;
use bridge_core::VerifierContext;
use bridge_steps_deposit::{HeaderVerifier, MidstateVerifier};
use types_base::public_inputs::dogeos::chunk::DogeOsChunkInfo;
use crate::scroll;

/// The witness type accepted by the chunk-circuit.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DogeOsChunkWitness {
    /// Scroll ChunkWitness
    pub inner: scroll::ChunkWitness,
    // Other DogeOs-specific fields can be added here
    pub verifier_context: SerdeWrapper<VerifierContext>,
    pub header: SerdeWrapper<StepInputEnvelope<HeaderVerifier>>,
    pub midstate: SerdeWrapper<StepInputEnvelope<MidstateVerifier>>,
}

impl TryFrom<DogeOsChunkWitness> for DogeOsChunkInfo {
    type Error = String;

    fn try_from(value: DogeOsChunkWitness) -> Result<Self, Self::Error> {
        super::execute(value)
    }
}
