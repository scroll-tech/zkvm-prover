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

    assert_eq!(batch.chunk_proofs.len(), pi_builder.chunks_pi.len());
    for (chunk_pi_exp, chunk_pi_got) in batch
        .chunk_proofs
        .iter()
        .map(|proof| &proof.public_values)
        .zip(pi_builder.chunks_pi.iter())
    {
        for (chunk_pi_exp_byte, &chunk_pi_got_byte) in chunk_pi_exp.iter().zip(chunk_pi_got.iter())
        {
            assert_eq!(chunk_pi_exp_byte.to_native(), chunk_pi_got_byte as u32);
        }
    }

    pi_builder
}
