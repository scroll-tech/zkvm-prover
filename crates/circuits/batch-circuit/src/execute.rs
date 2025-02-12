use scroll_zkvm_circuit_input_types::{
    batch::{ArchivedBatchWitness, ArchivedReferenceHeader, BatchInfo, MAX_AGG_CHUNKS},
    chunk::ChunkInfo,
};

use crate::builder::v3::BatchInfoBuilderV3;

pub fn execute(witness: &ArchivedBatchWitness) -> BatchInfo {
    let chunk_infos: Vec<ChunkInfo> = witness.chunk_infos.iter().map(|ci| ci.into()).collect();

    match &witness.reference_header {
        ArchivedReferenceHeader::V3(header) => BatchInfoBuilderV3::build::<MAX_AGG_CHUNKS>(
            &header.into(),
            &chunk_infos,
            &witness.blob_bytes,
        ),
        ArchivedReferenceHeader::V7(_header) => todo!(),
    }
}
