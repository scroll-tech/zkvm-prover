mod batch;
mod blob_consistency;
mod blob_data;
mod chunk;
mod utils;

use batch::{ArchivedBatchWitness, AsLastBatchHeader, MAX_AGG_CHUNKS, PIBuilder, ArchivedReferenceHeader};
use chunk::ChunkInfo;
use openvm::io;
use rkyv::{access, rancor::BoxedError};

#[allow(unused_imports, clippy::single_component_path_imports)]
use {
    openvm::platform as openvm_platform,
    openvm_keccak256_guest, // trigger extern native-keccak256
};

openvm_algebra_guest::moduli_setup::moduli_init! {
    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
}

openvm::entry!(main);

fn comput_batch_pi(batch: &ArchivedBatchWitness) {
    let chunks_info: Vec<ChunkInfo> = batch.chunks_info.into_iter().map(|ci| ci.into()).collect();

    let pi = match &batch.reference_header {
        ArchivedReferenceHeader::V3(header) => {
            PIBuilder::construct_with_header_v3::<MAX_AGG_CHUNKS>(
                AsLastBatchHeader(header),
                chunks_info.iter(),
                &batch.blob_bytes,
                header.blob_versioned_hash.into(),
                header.l1_message_popped.into(),
                header.total_l1_message_popped.into(),
                header.last_block_timestamp.into(),
            )
        }
    };

    for (i, part) in pi.batch_hash.chunks_exact(4).enumerate() {
        openvm::io::reveal(u32::from_be_bytes(part.try_into().unwrap()), i)
    }
}
fn main() {
    let input_data = io::read_vec();

    let batch = access::<ArchivedBatchWitness, BoxedError>(&input_data).unwrap();
    comput_batch_pi(&batch);
}
