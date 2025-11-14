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
