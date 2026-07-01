//! Backend-neutral interface for scroll-zkvm's multi-zkVM support.
//!
//! `scroll-zkvm-prover` is built on OpenVM, and second/third backends (SP1, ZisK)
//! live in **isolated sibling workspaces** (`sp1/`, `zisk/`) because each zkVM pulls
//! an incompatible `revm`/`alloy` dependency graph. What they can and do share is:
//!
//! - the pure Scroll business logic in `crates/types/*` (backend-agnostic since the
//!   SP1 commit; OpenVM-specific crypto is behind the `openvm` feature), and
//! - this crate, which pins down a *backend-neutral* host-side contract so that
//!   "add the Nth zkVM backend" is a mechanical exercise: copy a backend workspace
//!   and implement [`ZkvmBackend`].
//!
//! This crate deliberately depends on **no** zkVM SDK. It is plain types plus a
//! trait, so it compiles inside the main (OpenVM) workspace without perturbing the
//! OpenVM proving path, and can be `path`-depended from the `sp1/` and `zisk/`
//! workspaces just like `crates/types/*` are.
//!
//! The three Scroll proof tiers ([`CircuitTier`]) map onto every backend the same way:
//!
//! ```text
//! chunk  -> STARK proof (per-chunk)
//!   |         aggregated by
//! batch  -> STARK proof (verifies child chunk proofs)
//!   |         aggregated by
//! bundle -> SNARK / EVM proof (verifies child batch proof, verifiable on-chain)
//! ```

use serde::{Deserialize, Serialize};

/// The Scroll proof tiers, shared across every backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CircuitTier {
    /// Per-chunk circuit: executes a `ChunkWitness`, commits the chunk `pi_hash`.
    Chunk,
    /// Batch circuit: aggregates child chunk proofs, commits the batch `pi_hash`.
    Batch,
    /// Bundle circuit: aggregates a batch proof, wraps to an on-chain proof.
    Bundle,
}

impl CircuitTier {
    /// Lower-case tier name (`"chunk"`, `"batch"`, `"bundle"`), matching the
    /// per-tier directory layout used by every backend workspace.
    pub fn as_str(&self) -> &'static str {
        match self {
            CircuitTier::Chunk => "chunk",
            CircuitTier::Batch => "batch",
            CircuitTier::Bundle => "bundle",
        }
    }

    /// Whether this tier's proof is the final, on-chain-verifiable (SNARK) proof.
    pub fn is_evm_tier(&self) -> bool {
        matches!(self, CircuitTier::Bundle)
    }
}

impl std::str::FromStr for CircuitTier {
    type Err = BackendError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "chunk" => Ok(CircuitTier::Chunk),
            "batch" => Ok(CircuitTier::Batch),
            "bundle" => Ok(CircuitTier::Bundle),
            other => Err(BackendError::UnknownTier(other.to_string())),
        }
    }
}

/// Identifier for a loaded backend program (a compiled guest + its verifying key).
///
/// The concrete shape of a verifying key differs per backend (SP1 exposes a 32-byte
/// `vk.bytes32()`, OpenVM/ZisK expose commitment arrays), so this keeps both a
/// human-readable hash and an opaque commitment word array.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramKey {
    /// Backend name that produced this key (e.g. `"openvm"`, `"sp1"`, `"zisk"`).
    pub backend: String,
    /// Which tier this program implements.
    pub tier: Option<CircuitTier>,
    /// Human-readable verifying-key hash (e.g. SP1 `vk.bytes32()`), if the backend has one.
    pub vk_hash: String,
    /// Opaque commitment words used to distinguish which circuit produced a proof.
    pub exe_commitment: Vec<u32>,
}

/// A backend-neutral proof envelope: **opaque bytes plus public metadata**.
///
/// Each backend serialises its own native proof into `bytes`; the shared host code
/// only ever moves these around, hashes `public_values`, and routes them to the
/// matching verifier. `Stark` proofs are the aggregatable/recursive kind consumed by
/// a higher tier; `Snark` is the final on-chain-verifiable proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofEnum {
    /// Aggregatable STARK proof (SP1 "compressed", OpenVM stark, ZisK VADCOP stark).
    Stark(StarkProof),
    /// On-chain-verifiable SNARK proof (SP1 Plonk/Groth16, OpenVM Halo2, ZisK Plonk).
    Snark(EvmProof),
}

impl ProofEnum {
    /// The committed public values for this proof, regardless of variant.
    pub fn public_values(&self) -> &[u8] {
        match self {
            ProofEnum::Stark(p) => &p.public_values,
            ProofEnum::Snark(p) => &p.instances,
        }
    }

    /// Whether this is the final on-chain-verifiable proof.
    pub fn is_snark(&self) -> bool {
        matches!(self, ProofEnum::Snark(_))
    }
}

/// Raw aggregatable STARK proof bytes plus its committed public values.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StarkProof {
    #[serde(with = "serde_base64")]
    pub bytes: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub public_values: Vec<u8>,
}

/// SNARK proof formatted for EVM verification.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvmProof {
    #[serde(with = "serde_base64")]
    pub proof: Vec<u8>,
    #[serde(with = "serde_base64")]
    pub instances: Vec<u8>,
    /// Human-readable verifying-key hash for the on-chain verifier routing.
    pub vkey_hash: String,
}

/// Timing/size statistics collected while proving, in a backend-neutral shape.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProofStat {
    /// Backend cycle/step/instruction count for the executed guest.
    pub total_cycles: u64,
    /// Wall-clock execution (no proof) time in milliseconds.
    pub execution_time_mills: u64,
    /// Wall-clock proving time in milliseconds.
    pub proving_time_mills: u64,
    /// Serialized proof size in bytes.
    pub proof_size_bytes: u64,
}

impl ProofStat {
    /// Proving throughput in MHz (cycles / proving-second), matching the units the
    /// OpenVM and SP1 integration logs already print.
    pub fn proving_mhz(&self) -> f64 {
        let secs = self.proving_time_mills as f64 / 1000.0;
        if secs > 0.0 {
            self.total_cycles as f64 / secs / 1_000_000.0
        } else {
            0.0
        }
    }
}

/// Errors surfaced by the neutral interface. Backends wrap their SDK errors into
/// [`BackendError::Backend`].
#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("unknown circuit tier: {0}")]
    UnknownTier(String),
    #[error("tier {tier:?} not supported by the {backend} backend yet")]
    Unsupported { backend: String, tier: CircuitTier },
    #[error("backend error: {0}")]
    Backend(String),
}

/// Host-side contract every zkVM backend implements.
///
/// A backend owns its guest ELFs/`.vmexe`, its SDK proving client, and its verifier.
/// The shared prover/orchestration layer only ever talks to this trait plus
/// [`ProofEnum`], so swapping or adding a backend does not touch the aggregation
/// pipeline. `input` is the already-encoded guest stdin for the given tier (each
/// backend defines its own framing); returning opaque `ProofEnum` keeps proof
/// formats out of the shared layer.
pub trait ZkvmBackend {
    /// Backend name, e.g. `"openvm"`, `"sp1"`, `"zisk"`.
    fn name(&self) -> &str;

    /// Load/derive the program key (guest + verifying key) for a tier.
    fn setup(&self, tier: CircuitTier) -> Result<ProgramKey, BackendError>;

    /// Execute the guest without proving; returns (committed public values, cycle count).
    fn execute(&self, tier: CircuitTier, input: &[u8]) -> Result<(Vec<u8>, u64), BackendError>;

    /// Produce an aggregatable STARK proof for a tier.
    fn prove_stark(&self, tier: CircuitTier, input: &[u8]) -> Result<StarkProof, BackendError>;

    /// Produce the final on-chain-verifiable SNARK proof (typically only `Bundle`).
    fn prove_snark(&self, tier: CircuitTier, input: &[u8]) -> Result<EvmProof, BackendError> {
        let _ = input;
        Err(BackendError::Unsupported {
            backend: self.name().to_string(),
            tier,
        })
    }

    /// Verify a proof produced by this backend for the given tier.
    fn verify(&self, tier: CircuitTier, proof: &ProofEnum) -> Result<(), BackendError>;
}

mod serde_base64 {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        STANDARD.encode(bytes).serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(deserializer)?;
        STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_roundtrip() {
        for (s, t) in [
            ("chunk", CircuitTier::Chunk),
            ("batch", CircuitTier::Batch),
            ("bundle", CircuitTier::Bundle),
        ] {
            assert_eq!(s.parse::<CircuitTier>().unwrap(), t);
            assert_eq!(t.as_str(), s);
        }
        assert!("nope".parse::<CircuitTier>().is_err());
        assert!(CircuitTier::Bundle.is_evm_tier());
        assert!(!CircuitTier::Chunk.is_evm_tier());
    }

    #[test]
    fn proof_envelope_roundtrip() {
        let proof = ProofEnum::Snark(EvmProof {
            proof: vec![1, 2, 3],
            instances: vec![4, 5],
            vkey_hash: "0x1234".to_string(),
        });
        let json = serde_json::to_string(&proof).unwrap();
        let back: ProofEnum = serde_json::from_str(&json).unwrap();
        assert!(back.is_snark());
        assert_eq!(back.public_values(), &[4, 5]);
    }

    #[test]
    fn proving_mhz() {
        let stat = ProofStat {
            total_cycles: 2_000_000,
            proving_time_mills: 1000,
            ..Default::default()
        };
        assert!((stat.proving_mhz() - 2.0).abs() < 1e-9);
    }
}
