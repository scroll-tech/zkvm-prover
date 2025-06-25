use rkyv::util::AlignedVec;
use std::{borrow::Cow, collections::BTreeMap};

#[cfg(target_os = "zkvm")]
static ENVIRON_STUB: std::sync::OnceLock<&'static ArchivedEnvironStub> = OnceLock::new();

/// A list of environment variable keys that are allowed to be stored in the `EnvironStub`.
#[cfg(not(target_os = "zkvm"))]
static ENVIRON_KEY_ALLOW_LIST: &[&str] = &["SCROLL_CHUNK_STATE_COMMITMENT"];

/// A stub for the environ API.
#[derive(
    Debug, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize, serde::Serialize, serde::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct EnvironStub(BTreeMap<String, String>);

impl EnvironStub {
    /// Creates a new `EnvironStub` from the current environment variables.
    #[cfg(not(target_os = "zkvm"))]
    pub fn from_env() -> Result<AlignedVec, rkyv::rancor::Error> {
        let map = std::env::vars()
            .filter(|(k, _)| ENVIRON_KEY_ALLOW_LIST.contains(&k.as_str()))
            .collect();
        let this = Self(map);
        rkyv::to_bytes(&this)
    }

    /// Sets up the `EnvironStub` with serialized environment variables.
    #[cfg(target_os = "zkvm")]
    pub fn setup(env: Vec<u8>) {
        static INIT: std::sync::OnceLock<Vec<u8>> = OnceLock::new();
        INIT.set(env).expect("EnvironStub already initialized");

        let buffer = INIT.get().expect("EnvironStub not initialized");
        let archived = rkyv::access::<ArchivedEnvironStub, rkyv::rancor::BoxedError>(buffer)
            .expect("Failed to access ArchivedEnvironStub");
        ENVIRON_STUB.set(archived).expect("EnvironStub already set");
    }

    /// Sets up the `EnvironStub` with serialized environment variables.
    #[cfg(not(target_os = "zkvm"))]
    pub fn setup(_env: Vec<u8>) {
        // This function is a no-op in non-ZKVM environments.
        // The environment variables are accessed directly using std::env::var.
        // No setup is needed.
    }

    /// Returns the value associated with the given key, if it exists.
    #[cfg(target_os = "zkvm")]
    pub fn get(key: &str) -> Option<Cow<str>> {
        let archived = ENVIRON_STUB.get().expect("EnvironStub not initialized");
        archived.0.get(key).map(|s| Cow::Borrowed(s.as_str()))
    }

    /// Returns the value associated with the given key, if it exists.
    #[cfg(not(target_os = "zkvm"))]
    pub fn get(key: &str) -> Option<Cow<str>> {
        std::env::var(key).ok().map(Cow::Owned)
    }
}
