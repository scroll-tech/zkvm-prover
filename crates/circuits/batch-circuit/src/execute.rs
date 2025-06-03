use scroll_zkvm_types_batch::{ArchivedBatchWitness, ArchivedReferenceHeader};
use scroll_zkvm_types_circuit::public_inputs::{batch::BatchInfo, chunk::ChunkInfo};

use crate::builder::{BatchInfoBuilderV6, BatchInfoBuilderV7};

pub fn execute(witness: &ArchivedBatchWitness) -> BatchInfo {
    let chunk_infos: Vec<ChunkInfo> = witness.chunk_infos.iter().map(|ci| ci.into()).collect();

    match &witness.reference_header {
        ArchivedReferenceHeader::V6(header) => {
            BatchInfoBuilderV6::build(&header.into(), &chunk_infos, &witness.blob_bytes)
        }
        ArchivedReferenceHeader::V7(header) => BatchInfoBuilderV7::build(
            &header.into(),
            &chunk_infos,
            &witness.blob_bytes,
            &witness.point_eval_witness.kzg_commitment,
            &witness.point_eval_witness.kzg_proof,
        ),
    }
}
