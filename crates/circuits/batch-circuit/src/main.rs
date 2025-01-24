use alloy_primitives::B256;
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

openvm_algebra_guest::moduli_macros::moduli_init! {
    "52435875175126190479447740508185965837690552500527637822603658699938581184513"
}

openvm::entry!(main);

fn execute(batch: &ArchivedBatchWitness) -> B256 {
    let chunk_infos: Vec<ChunkInfo> = batch.chunk_infos.iter().map(|ci| ci.into()).collect();

    let pi = match &batch.reference_header {
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

    pi.public_input_hash()
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
    openvm_rv32im_guest::hint_store_u32!((&mut len) as *mut u32 as u32);
    let num_words = (len + 3) / 4;
    let size = (num_words * 4) as usize;
    let layout = Layout::from_size_align(size, 16).unwrap();
    let ptr_start = unsafe { System.alloc(layout) };
    let mut ptr = ptr_start;
    for _ in 0..num_words {
        openvm_rv32im_guest::hint_store_u32!(ptr as u32);
        ptr = unsafe { ptr.add(4) };
    }
    unsafe { Vec::from_raw_parts(ptr_start, len as usize, size) }
}

// dummy implement to avoid complains
#[cfg(not(target_os = "zkvm"))]
fn read_witnesses() -> Vec<u8> {
    openvm::io::read_vec()
}

const EXE_COMMIT: [u32; 8] = [
    397570296, 303176697, 1964773027, 1141065112, 1871270311, 1130635204, 1728891034, 568787834,
];
const LEAF_COMMIT: [u32; 8] = [
    1927402829, 499234175, 923282328, 1081788839, 582968208, 549279052, 209451000, 2007289153,
];

// will terminate inside if fail
fn exec_kernel(input: &[u32], expect_output: &[u32]) {
    let mut _input_ptr: *const u32 = input.as_ptr();
    let mut _output_ptr: *const u32 = expect_output.as_ptr();
    let mut _buf1: u32 = 0;
    let mut _buf2: u32 = 0;
    #[cfg(all(target_os = "zkvm", target_arch = "riscv32"))]
    unsafe {
        std::arch::asm!(
            include_str!("../../../tools/generate-verifier-asm/root_verifier.asm"),
            inout("x28") _input_ptr,
            inout("x29") _output_ptr,
            inout("x30") _buf1,
            inout("x31") _buf2,
        )
    }
}

fn verify_chunk_proof(flatten_proof: &[u32], public_inputs: &[u32]) {
    let mut full_pi = vec![];
    let default_pi_len = 32;
    assert_eq!(default_pi_len, public_inputs.len());
    full_pi.extend(EXE_COMMIT);
    full_pi.extend(LEAF_COMMIT);
    full_pi.extend_from_slice(public_inputs);
    exec_kernel(flatten_proof, &full_pi);
    println!("verified chunk proof successfully");
}

fn main() {
    let batch_witness_bytes = read_witnesses();
    let batch_witness = access::<ArchivedBatchWitness, BoxedError>(&batch_witness_bytes)
        .expect("rkyv decode BatchWitness");

    for flattened_proof in batch_witness.chunk_proofs.iter() {
        println!(
            "input.flatten_proof[..30]: {:?}",
            &flattened_proof.flatten_proof[..30]
        );
        println!(
            "input.public_values[..30]: {:?}",
            &flattened_proof.public_values[..30]
        );
        verify_chunk_proof(
            flattened_proof
                .flatten_proof
                .iter()
                .map(|u32_le| u32_le.to_native())
                .collect::<Vec<u32>>()
                .as_slice(),
            flattened_proof
                .public_values
                .iter()
                .map(|u32_le| u32_le.to_native())
                .collect::<Vec<u32>>()
                .as_slice(),
        );
    }

    let pi_hash = execute(batch_witness);

    for (i, part) in pi_hash.chunks_exact(4).enumerate() {
        openvm::io::reveal(u32::from_le_bytes(part.try_into().unwrap()), i)
    }
}
