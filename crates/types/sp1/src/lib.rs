//! Shared types for the SP1 zkVM backend.
//!
//! This crate intentionally avoids a direct dependency on `sp1-sdk` so that it
//! can live in the main workspace alongside the OpenVM backend.  Host code that
//! needs SP1-specific SDK types should convert to/from these plain structs.

use serde::{Deserialize, Serialize};

/// Identifier for a loaded SP1 program (ELF + vkey).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProgramKey {
    /// 32-byte verifying key hash (sp1-sdk `vk.bytes32()`).
    pub vk_hash: String,
    /// Commitment used to distinguish which circuit produced a proof.
    pub exe_commitment: [u32; 8],
}

/// SP1 proof variant used internally by Scroll.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ProofEnum {
    /// SP1 core proof (a single shard proof).
    Core(CoreProof),
    /// SP1 compressed proof, suitable for aggregation/recursion.
    Compressed(CompressedProof),
    /// SP1 Plonk proof, verifiable on-chain.
    Plonk(EvmProof),
}

/// Raw SP1 core proof bytes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CoreProof {
    #[serde(with = "crate::serde_base64")]
    pub bytes: Vec<u8>,
    #[serde(with = "crate::serde_base64")]
    pub public_values: Vec<u8>,
    pub cycles: u64,
}

/// Raw SP1 compressed proof bytes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CompressedProof {
    #[serde(with = "crate::serde_base64")]
    pub bytes: Vec<u8>,
    #[serde(with = "crate::serde_base64")]
    pub public_values: Vec<u8>,
}

/// SP1 Plonk proof formatted for EVM verification.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EvmProof {
    #[serde(with = "crate::serde_base64")]
    pub proof: Vec<u8>,
    #[serde(with = "crate::serde_base64")]
    pub instances: Vec<u8>,
    pub vkey_hash: String,
}

/// Statistics collected while proving.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProofStat {
    pub total_cycles: u64,
    pub execution_time_mills: u64,
    pub proving_time_mills: u64,
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
    fn roundtrip_evmp_proof() {
        let proof = EvmProof {
            proof: vec![1, 2, 3],
            instances: vec![4, 5],
            vkey_hash: "0x1234".to_string(),
        };
        let json = serde_json::to_string(&proof).unwrap();
        let back: EvmProof = serde_json::from_str(&json).unwrap();
        assert_eq!(back.proof, proof.proof);
        assert_eq!(back.instances, proof.instances);
    }
}
