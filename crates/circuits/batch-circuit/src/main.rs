use rkyv::{access, rancor::BoxedError};
use scroll_zkvm_circuit_input_types::batch::AsLastBatchHeader;

mod batch;
use batch::{ArchivedBatchWitness, ArchivedReferenceHeader, ChunkInfo, MAX_AGG_CHUNKS, PIBuilder};

mod blob_consistency;

mod payload;

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
    let chunks_info: Vec<ChunkInfo> = batch.chunks_info.iter().map(|ci| ci.into()).collect();

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

    for (i, part) in pi.public_input_hash().chunks_exact(4).enumerate() {
        openvm::io::reveal(u32::from_be_bytes(part.try_into().unwrap()), i)
    }
}

// Read the witnesses from the hint stream.
// rkyv needs special alignment for its data structures, use a pre-aligned
// buffer with rkyv::access_unchecked is more efficient than rkyv::access
#[cfg(target_os = "zkvm")]
#[inline(always)]
fn read_witnesses() -> Vec<u8> {
    use std::alloc::{GlobalAlloc, Layout, System};
    openvm_rv32im_guest::hint_input();
    let mut len: u32 = 0;
    openvm_rv32im_guest::hint_store_u32!((&mut len) as *mut u32 as u32, 0);
    let num_words = (len + 3) / 4;
    let size = (num_words * 4) as usize;
    let layout = Layout::from_size_align(size, 16).unwrap();
    let ptr_start = unsafe { System.alloc(layout) };
    let mut ptr = ptr_start;
    for _ in 0..num_words {
        openvm_rv32im_guest::hint_store_u32!(ptr as u32, 0);
        ptr = unsafe { ptr.add(4) };
    }
    unsafe { Vec::from_raw_parts(ptr_start, len as usize, size) }
}

// dummy implement to avoid complains
#[cfg(not(target_os = "zkvm"))]
fn read_witnesses() -> Vec<u8> {
    openvm::io::read_vec()
}

fn main() {
    let input_data = read_witnesses();

    let batch = access::<ArchivedBatchWitness, BoxedError>(&input_data).unwrap();
    comput_batch_pi(batch);
}
