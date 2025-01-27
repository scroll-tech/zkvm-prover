use scroll_zkvm_circuit_input_types::{
    batch::{ArchivedBatchWitness, ArchivedReferenceHeader, AsLastBatchHeader},
    chunk::ChunkInfo,
};

use crate::batch::{MAX_AGG_CHUNKS, PIBuilder};

pub fn execute(batch: &ArchivedBatchWitness) -> PIBuilder {
    let chunk_infos: Vec<ChunkInfo> = batch.chunk_infos.iter().map(|ci| ci.into()).collect();

    let pi_builder = match &batch.reference_header {
        ArchivedReferenceHeader::V3(header) => {
            PIBuilder::construct_with_header_v3::<MAX_AGG_CHUNKS>(
                AsLastBatchHeader(header),
                chunk_infos.iter(),
                &batch.blob_bytes,
                header.blob_versioned_hash.into(),
                header.l1_message_popped.into(),
                header.total_l1_message_popped.into(),
                header.last_block_timestamp.into(),
            )
        }
    };

    pi_builder
}
