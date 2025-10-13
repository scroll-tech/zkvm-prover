extern crate ceno_rt;

use ceno_crypto::ceno_crypto;
use rkyv::Archived;
use scroll_zkvm_types_chunk::{Address, ChunkWitness, alloy_consensus, execute, revm_precompile};

ceno_crypto!(
    revm_precompile = revm_precompile,
    alloy_consensus = alloy_consensus,
    address_type = Address,
);

fn main() {
    CenoCrypto::install();

    let witness_bytes: &Archived<Vec<u8>> = ceno_rt::read();

    let config = bincode::config::standard();
    let (witness, _): (ChunkWitness, _) = bincode::serde::decode_from_slice(witness_bytes, config)
        .expect("ChunkCircuit: deserialisation of witness bytes failed");

    let _fork_name = witness.fork_name;
    let _chunk_info = execute(witness).expect("execution failed");

    // let pi_hash = (chunk_info, fork_name).pi_hash();
    // ceno_rt::commit(&pi_hash);
}
