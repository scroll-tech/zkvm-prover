use serde::{Deserialize, Serialize};

pub mod config {
    /// Axiom configuration ID for [openvm.toml](../../circuits/chunk-circuit/openvm.toml).
    /// Should be updated when the openvm.toml changes.
    pub const CHUNK: &str = "cfg_01k9b6y2tcnw8b969vnk6d7eyq";
    /// Axiom configuration ID for [openvm.toml](../../circuits/batch-circuit/openvm.toml).
    /// Should be updated when the openvm.toml changes.
    pub const BATCH: &str = "cfg_01k9b6wa8hx37z42kd41cqrkfs";
    /// Axiom configuration ID for [openvm.toml](../../circuits/bundle-circuit/openvm.toml).
    /// Should be updated when the openvm.toml changes.
    pub const BUNDLE: &str = "cfg_01k9b6xjt0va25sy94tztwehs7";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AxiomProgram {
    program_id: String,
    config_id: String,
}

impl AxiomProgram {
    pub fn new<P: Into<String>, C: Into<String>>(program_id: P, config_id: C) -> Self {
        Self {
            program_id: program_id.into(),
            config_id: config_id.into(),
        }
    }

    pub fn chunk<S: Into<String>>(program_id: S) -> Self {
        Self::new(program_id, config::CHUNK)
    }

    pub fn batch<S: Into<String>>(program_id: S) -> Self {
        Self::new(program_id, config::BATCH)
    }

    pub fn bundle<S: Into<String>>(program_id: S) -> Self {
        Self::new(program_id, config::BUNDLE)
    }

    pub fn program_id(&self) -> &str {
        &self.program_id
    }

    pub fn config_id(&self) -> &str {
        &self.config_id
    }
}

/// Get the Axiom configuration ID for the given circuit kind.
///
/// # Panics
///
/// Panics if the kind is not one of "chunk", "batch", or "bundle".
pub fn get_config_id(kind: &str) -> &str {
    use config::{BATCH, BUNDLE, CHUNK};

    match kind {
        "chunk" => CHUNK,
        "batch" => BATCH,
        "bundle" => BUNDLE,
        _ => panic!("Unknown config kind: {}", kind),
    }
}
