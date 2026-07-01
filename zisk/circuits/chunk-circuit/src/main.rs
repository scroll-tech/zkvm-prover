//! ZisK chunk circuit — the single-tier PoC of the ZisK backend.
//!
//! Line-for-line equivalent of `sp1/circuits/chunk-circuit/src/main.rs`, but using
//! the ZisK guest I/O (`ziskos::io`) instead of SP1's. It deserialises a real Scroll
//! `ChunkWitness`, executes the chunk (`ChunkInfo::try_from` runs stateless block
//! execution via `sbv`/`revm`), and commits the 32-byte chunk `pi_hash` as the guest
//! public output.
//!
//! Host contract: the input file is a single ZisK-framed value — an 8-byte LE length
//! prefix followed by the (8-byte-aligned) `bincode::config::standard()` encoding of a
//! `ChunkWitness`. `ziskos::io::read_input_slice()` returns exactly those payload bytes.

#![no_main]
ziskos::entrypoint!(main);

use alloy_primitives::B256;
use scroll_zkvm_types_base::public_inputs::{PublicInputs, Version, scroll::chunk::ChunkInfo};
use scroll_zkvm_types_chunk::scroll::ChunkWitness;

/// getrandom 0.3.x "custom" backend symbol.
///
/// The sbv/revm graph pulls getrandom 0.3.x (e.g. for hashbrown's default RandomState).
/// Its custom backend calls an externally-defined `__getrandom_v03_custom`; ziskos only
/// registers the getrandom **0.2** backend (`register_custom_getrandom!`), so we provide
/// the 0.3 symbol here and wire it to ziskos' `sys_rand` syscall. The chunk guest only
/// *verifies* state (no key generation / signing), so this randomness is not
/// security-critical; it exists so the graph links and any incidental RNG use works.
#[no_mangle]
unsafe extern "Rust" fn __getrandom_v03_custom(
    dest: *mut u8,
    len: usize,
) -> Result<(), getrandom03::Error> {
    extern "C" {
        fn sys_rand(recv_buf: *mut u8, words: usize);
    }
    sys_rand(dest, len);
    Ok(())
}

pub fn main() {
    // Read the bincode-encoded ChunkWitness from the ZisK input stream.
    let witness_bytes = ziskos::io::read_input_slice();
    let (witness, _): (ChunkWitness, _) =
        bincode::serde::decode_from_slice(witness_bytes.as_ref(), bincode::config::standard())
            .expect("ChunkCircuit: deserialisation of witness bytes failed");

    // Execute the chunk and derive the public inputs.
    let version = Version::from(witness.version);
    assert_eq!(version.fork, witness.fork_name);
    let chunk_info = ChunkInfo::try_from(witness).expect("failed to execute chunk");

    // Commit the 32-byte public-input hash as the guest output.
    let pi_hash: B256 = (chunk_info, version).pi_hash();
    ziskos::io::commit_slice(pi_hash.as_slice());
}
