use scroll_zkvm_circuit_input_types::{
    batch::{ArchivedBatchWitness, ArchivedReferenceHeader, BatchInfo},
    chunk::ChunkInfo,
};

use crate::builder::BatchInfoBuilder;

pub fn execute(witness: &ArchivedBatchWitness) -> BatchInfo {
    let chunk_infos: Vec<ChunkInfo> = witness.chunk_infos.iter().map(|ci| ci.into()).collect();

    match &witness.reference_header {
        #[cfg(not(feature = "euclidv2"))]
        ArchivedReferenceHeader::V3(header) => {
            BatchInfoBuilder::build(&header.into(), &chunk_infos, &witness.blob_bytes)
        }
        #[cfg(feature = "euclidv2")]
        ArchivedReferenceHeader::V7(header) => BatchInfoBuilder::build(
            &header.into(),
            &chunk_infos,
            &witness.blob_bytes,
            &witness.point_eval_witness.kzg_commitment,
            &witness.point_eval_witness.kzg_proof,
        ),
        _ => unreachable!(),
    }
}
