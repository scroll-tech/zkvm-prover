//! ZisK batch circuit — recursion PoC.
//!
//! Demonstrates that `zisk-verifier` / `proofman-verifier` can be compiled into a ZisK
//! guest and that the verification API correctly verifies a real child proof. The host
//! (see `zisk/recursion-test`) extracts the child proof + vkey from a `zisk_common::Proof`,
//! frames them, and feeds them to this guest.
//!
//! End-to-end status: verified against both a tiny bundle-stub child proof and a real
//! single-block Scroll chunk proof generated on GPU.
//!
//! TODO(batch): replace the placeholder commitment with real Scroll batch aggregation:
//!   - verify one or more child chunk proofs in-guest,
//!   - validate the batch payload / blob-KZG,
//!   - derive `BatchInfo` and commit the batch `pi_hash`.

#![no_main]
ziskos::entrypoint!(main);

use alloy_primitives::keccak256;
use zisk_verifier::{verify_vadcop_final_proof, PROGRAM_VK_LEN};

pub fn main() {
    let input = ziskos::io::read_input_slice();
    let words: Vec<u64> = input
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().expect("batch input not 8-byte aligned")))
        .collect();

    // Expected framing: [proof_len] [proof u64s...] [vk_len] [vk u64s...]
    let mut p = 0usize;
    let proof_len = words[p] as usize;
    p += 1;
    let proof = &words[p..p + proof_len];
    p += proof_len;
    let vk_len = words[p] as usize;
    p += 1;
    let vk = &words[p..p + vk_len];

    let ok = if vk_len == PROGRAM_VK_LEN {
        verify_vadcop_final_proof(proof, vk)
    } else {
        false
    };

    // Commit a 32-byte digest that encodes whether verification succeeded.
    // In the real batch circuit this would be the batch pi_hash after validating
    // the child chunk proofs + batch payload.
    let mut out = [0u8; 32];
    out[0] = if ok { 1 } else { 0 };
    let digest = keccak256(input.as_ref());
    out[1..].copy_from_slice(&digest.as_slice()[..31]);
    ziskos::io::commit_slice(&out);
}
