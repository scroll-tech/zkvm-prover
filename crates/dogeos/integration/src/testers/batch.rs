use std::sync::Arc;
use bridge_adapters_zk::serde::SerdeWrapper;
use bridge_adapters_zk::{StepInputEnvelope};
use bridge_core::{BuilderContext, BuilderStep};
use bridge_protocol::{DaInclusionStmtV1, PipelineMetadata};
use bridge_steps_da::{DaInclusionBuilder, DaInclusionVerifier, SyntheticBlobSource};
use scroll_zkvm_integration::{ProverTester, PROGRAM_COMMITMENTS};
use scroll_zkvm_integration::utils::build_batch_witnesses;
use scroll_zkvm_types::dogeos::batch::dogeos::{DogeOsBatchWitness, DogeOsBatchWitnessExtras};
use scroll_zkvm_types::dogeos::chunk::execute;
use scroll_zkvm_types::public_inputs::dogeos::batch::DogeOsBatchInfo;
use scroll_zkvm_types::utils::serialize_vk;

pub struct BatchProverTester;

impl ProverTester for BatchProverTester {
    type Metadata = DogeOsBatchInfo;

    type Witness = DogeOsBatchWitness;

    const NAME: &str = "batch";

    const PATH_PROJECT_ROOT: &str = "crates/dogeos/circuits/batch-circuit";

    const DIR_ASSETS: &str = "batch";
}

fn mock_inclusion_envelope() -> eyre::Result<StepInputEnvelope<DaInclusionVerifier>> {
   let statement = DaInclusionStmtV1 {
        metadata: PipelineMetadata {
            pipeline: "da".into(), ..PipelineMetadata::default() },
        celestia_height: 100,
        namespace: [0u8; 10],
        share_version: 1,
        commitment: [0u8; 32],
        data_root: [0u8; 32],
        expected_signer: None,
        bridge_state_hash: [0u8; 32],
        versioned_hash_witness: None,
    };

    let source = Arc::new(SyntheticBlobSource::new());
    let builder = DaInclusionBuilder::new(source);
    let artifact = builder.build(&statement, &BuilderContext::default())?;
    Ok(StepInputEnvelope {
        statement,
        artifact,
    })
}

pub fn mock_batch_witness() -> eyre::Result<DogeOsBatchWitness> {
    let chunk_witness = super::chunk::mock_chunk_witness()?;

    let last_info = execute(chunk_witness.clone()).expect("execute chunk");
    // let chunks = vec![chunk_witness.clone()];

    let commitment = PROGRAM_COMMITMENTS["chunk"];
    let inner = build_batch_witnesses(
        &[chunk_witness.inner],
        &serialize_vk::serialize(&commitment),
        Default::default()
    )?;
    let extras = DogeOsBatchWitnessExtras {
        chunk_info_extras: vec![last_info.extras],
        verifier_context: SerdeWrapper(Default::default()),
        inclusion: SerdeWrapper(mock_inclusion_envelope()?),
    };

    Ok(DogeOsBatchWitness {
        inner,
        extras,
    })
}
