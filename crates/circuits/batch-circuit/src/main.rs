mod batch;
mod blob_consistency;
mod blob_data;
mod chunk;
mod utils;

use batch::{ArchivedBatchTask, AsLastBatchHeader, MAX_AGG_CHUNKS, PIBuilder};
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

fn comput_batch_pi(batch: &ArchivedBatchTask) {
    let header_v3 = batch.header_v3.as_ref().unwrap();
    let chunks_info: Vec<ChunkInfo> = batch.chunks_info.into_iter().map(|ci| ci.into()).collect();

    let _pi = PIBuilder::construct_with_header_v3::<MAX_AGG_CHUNKS>(
        AsLastBatchHeader(header_v3),
        chunks_info.iter(),
        &batch.blob_bytes,
        header_v3.blob_versioned_hash.into(),
        header_v3.l1_message_popped.into(),
        header_v3.total_l1_message_popped.into(),
        header_v3.last_block_timestamp.into(),
    );
}
fn main() {
    let input_data = io::read_vec();

    let batch = access::<ArchivedBatchTask, BoxedError>(&input_data).unwrap();
    comput_batch_pi(&batch);
}
