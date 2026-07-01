#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{
    PublicInputs, Version,
    scroll::chunk::ChunkInfo,
};
use scroll_zkvm_types_chunk::scroll::ChunkWitness;

pub fn main() {
    // Read the bincode-encoded ChunkWitness from host stdin.
    let witness_bytes = sp1_zkvm::io::read_vec();
    let (witness, _): (ChunkWitness, _) =
        bincode::serde::decode_from_slice(&witness_bytes, bincode::config::standard())
            .expect("ChunkCircuit: deserialisation of witness bytes failed");

    // Execute the chunk and derive the public inputs.
    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);
    let chunk_info = ChunkInfo::try_from(witness).expect("failed to execute chunk");

    // Commit the 32-byte public-input hash.
    let pi_hash: B256 = (chunk_info, version).pi_hash();
    sp1_zkvm::io::commit_slice(pi_hash.as_slice());
}
