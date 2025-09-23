extern crate ceno_rt;

use rkyv::Archived;
use scroll_zkvm_types_base::public_inputs::PublicInputs;
use scroll_zkvm_types_chunk::{execute, ChunkWitness};

fn main() {
    let witness_bytes: &Archived<Vec<u8>> = ceno_rt::read();

    let config = bincode::config::standard();
    let (witness, _): (ChunkWitness, _) =
        bincode::serde::decode_from_slice(witness_bytes, config)
            .expect("ChunkCircuit: deserialisation of witness bytes failed");

    let fork_name = witness.fork_name;
    let chunk_info = execute(witness).expect("execution failed");

    let _pi_hash = (chunk_info, fork_name).pi_hash();
    // ceno_rt::commit(&pi_hash);
}
