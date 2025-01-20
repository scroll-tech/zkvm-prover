mod error;
pub use error::Error;

mod prover;
pub use prover::gen_proof;

mod setup;
pub use setup::{compute_commitments, gen_agg_pk, read_app_config, read_app_exe, read_app_pk};
