use bridge_adapters_zk::StepInputEnvelope;
use bridge_adapters_zk::serde::SerdeWrapper;
use bridge_core::{BuilderContext, BuilderStep};
use bridge_protocol::{DaInclusionStmtV1, PipelineMetadata};
use bridge_steps_da::{DaInclusionBuilder, DaInclusionVerifier, SyntheticBlobSource};
use scroll_zkvm_integration::utils::build_batch_witnesses;
use scroll_zkvm_integration::{PROGRAM_COMMITMENTS, ProverTester};
use scroll_zkvm_types::dogeos::batch::dogeos::{DogeOsBatchWitness, DogeOsBatchWitnessExtras};
use scroll_zkvm_types::dogeos::chunk::{DogeOsChunkWitness, execute};
use scroll_zkvm_types::public_inputs::MultiVersionPublicInputs;
use scroll_zkvm_types::public_inputs::dogeos::batch::DogeOsBatchInfo;
use scroll_zkvm_types::types_agg::AggregationInput;
use scroll_zkvm_types::utils::serialize_vk;
use scroll_zkvm_types::version::Version;
use std::sync::Arc;

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
            pipeline: "da".into(),
            ..PipelineMetadata::default()
        },
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

pub fn mock_batch_witness(chunk_witness: &DogeOsChunkWitness) -> eyre::Result<DogeOsBatchWitness> {
    let last_info = execute(chunk_witness.clone()).expect("execute chunk");

    let commitment = PROGRAM_COMMITMENTS["chunk"];
    let mut inner = build_batch_witnesses(
        &[chunk_witness.inner.clone()],
        &serialize_vk::serialize(&commitment),
        Default::default(),
    )?;

    inner.chunk_proofs = vec![AggregationInput {
        public_values: last_info
            .pi_hash_by_version(Version::feynman())
            .as_slice()
            .iter()
            .map(|&b| b as u32)
            .collect::<Vec<_>>(),
        commitment,
    }];

    let extras = DogeOsBatchWitnessExtras {
        chunk_info_extras: vec![last_info.extras],
        verifier_context: SerdeWrapper(Default::default()),
        inclusion: SerdeWrapper(mock_inclusion_envelope()?),
    };

    Ok(DogeOsBatchWitness { inner, extras })
}
