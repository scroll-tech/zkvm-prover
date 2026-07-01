//! ZisK bundle circuit — **stub** (recursive aggregation + EVM wrap deferred).
//!
//! The bundle tier aggregates a batch proof and wraps to an on-chain-verifiable proof.
//! On SP1 the guest verifies the child batch proof via `verify_sp1_proof` and the host
//! wraps to Plonk. ZisK can in principle produce a Plonk SNARK
//! (`cargo-zisk prove --plonk`, ~1KB / ~250k gas), but that needs the ~36GB SNARK
//! proving key and a stable in-guest proof-verification API for the recursion — neither
//! is set up here yet. See `docs/zisk-backend-assessment.md`.
//!
//! This stub only reads its input and echoes a keccak commitment, keeping the backend
//! framework symmetric across tiers.
//!
//! TODO(recursion): verify child batch proof in-guest; derive `BundleInfo`; wrap to a
//! ZisK Plonk proof for EVM verification.

#![no_main]
ziskos::entrypoint!(main);

use alloy_primitives::keccak256;

pub fn main() {
    let input = ziskos::io::read_input_slice();
    // Placeholder public output until real bundle aggregation lands.
    let commitment = keccak256(input.as_ref());
    ziskos::io::commit_slice(commitment.as_slice());
}
