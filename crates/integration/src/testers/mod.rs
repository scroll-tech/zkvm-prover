pub mod batch;

pub mod bundle;

pub mod chunk;

/// Path to the testdata directory.
pub const PATH_TESTDATA: &str = "./testdata";

use scroll_zkvm_prover::Prover;
struct UnsafeSendWrappedProver(Prover);

unsafe impl Send for UnsafeSendWrappedProver {}