use std::path::PathBuf;

/// Errors encountered by the prover.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Covers various errors encountered during the setup phase.
    #[error("failed to read or deserialize {path}: {src}")]
    Setup { path: PathBuf, src: String },
    /// An error encountered while generating commitments to the app exe.
    #[error("failed to commit app exe: {0}")]
    Commit(String),
    /// An error encountered while performing the STARK aggregation keygen process.
    #[error("failed to generate STARK aggregation proving key: {0}")]
    Keygen(String),
    /// An error encountered during proof generation.
    #[error("failed to generate proof: {0}")]
    GenProof(String),
    /// An error encountered during proof verification.
    #[error("failed to verify proof: {0}")]
    VerifyProof(String),
}
