use scroll_zkvm_circuit_input_types::{
    batch::{ArchivedBatchWitness, ArchivedReferenceHeader, BatchInfo},
    chunk::ChunkInfo,
};

use crate::builder::v7::BatchInfoBuilderV7 as BatchInfoBuilder;

pub fn execute(witness: &ArchivedBatchWitness) -> BatchInfo {
    let chunk_infos: Vec<ChunkInfo> = witness.chunk_infos.iter().map(|ci| ci.into()).collect();

    match &witness.reference_header {
        ArchivedReferenceHeader::V7(header) => {
            BatchInfoBuilder::build(&header.into(), &chunk_infos, &witness.blob_bytes)
        }
        _ => unreachable!("only da-codec@v7 supported"),
    }
}
