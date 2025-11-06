pub mod config {
    pub const CHUNK: &str = "cfg_01k9b6y2tcnw8b969vnk6d7eyq";
    pub const BATCH: &str = "cfg_01k9b6wa8hx37z42kd41cqrkfs";
    pub const BUNDLE: &str = "cfg_01k9b6xjt0va25sy94tztwehs7";
}

pub fn get_config_id(kind: &str) -> &str {
    use config::{BATCH, BUNDLE, CHUNK};

    match kind {
        "chunk" => CHUNK,
        "batch" => BATCH,
        "bundle" => BUNDLE,
        _ => panic!("Unknown config kind: {}", kind),
    }
}
