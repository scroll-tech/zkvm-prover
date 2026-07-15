extern crate ceno_rt;

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{PublicInputs, Version, scroll::chunk::ChunkInfo};
use scroll_zkvm_types_chunk::scroll::ChunkWitness;

fn main() {
    let witness: ChunkWitness = ceno_rt::read();

    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);
    let chunk_info = ChunkInfo::try_from(witness).expect("failed to execute chunk");

    let pi_hash: B256 = (chunk_info, version).pi_hash();
    ceno_rt::commit(pi_hash.as_slice());
}
