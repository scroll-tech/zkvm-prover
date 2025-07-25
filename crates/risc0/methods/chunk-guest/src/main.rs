#![no_main]

use std::alloc::{GlobalAlloc, Layout, System};
use risc0_zkvm::guest::env;
use risc0_zkvm::serde::WordRead;
use scroll_zkvm_types_chunk::{execute, ArchivedChunkWitness};

risc0_zkvm::entry!(main);

fn main() {
    let witness_bytes = read_witness();
    let witness = rkyv::access::<ArchivedChunkWitness, rkyv::rancor::BoxedError>(&witness_bytes)
        .expect("ChunkCircuit: rkyv deserialisation of witness bytes failed");
    execute(witness).unwrap();
}

fn read_witness() -> Vec<u8> {
    let length = env::read::<u32>() as usize;
    let layout = Layout::from_size_align(length, 16).unwrap();
    let ptr = unsafe { System.alloc(layout) };
    env::read_slice(unsafe { std::slice::from_raw_parts_mut(ptr, length) });
    unsafe { Vec::from_raw_parts(ptr, length, length) }
}
