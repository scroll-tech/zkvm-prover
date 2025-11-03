use serde::{Deserialize, Serialize};
use std::{env, path::Path};
use super::TaskProver;
use scroll_zkvm_types::{ProvingTask, proof::ProofEnum, axiom};
use axiom_sdk::prove as axiom_prove;

/// Default Axiom API base URL
pub const DEFAULT_AXIOM_BASE_URL: &str = "https://api.axiom.xyz";

/// Simple blocking client for Axiom Proofs API
pub struct AxiomClient {
    base_url: String,
    api_key: String,
    program_id: String,
}

impl TaskProver for AxiomClient {
    fn name(&self) -> &str { &self.program_id}
    fn get_vk(&mut self) -> Vec<u8> {
        unimplemented!();
    }
    fn prove_task(&mut self, t: &ProvingTask, gen_snark: bool) -> eyre::Result<ProofEnum> {
        //axiom_prove::ProveSdk::
        unimplemented!();
    }
}

impl AxiomClient {
    /// Create a new client
    pub fn new(base_url: impl Into<String>) -> Self {
        let api_key = env::var("AXIOM_API_KEY").expect("AXIOM_API_KEY env var is required");
        let program_id = env::var("AXIOM_PROGRAM_ID").expect("AXIOM_PROGRAM_ID env var is required");
        Self { base_url: base_url.into(), api_key, program_id }
    }

    /// Generate a new proof via POST /v1/proofs
    ///
    /// - program_id: UUID of the program to prove
    /// - proof_type: Optional proof type ("stark" | "evm"). Defaults to "stark" if None.
    /// - witness: array of byte slices, each encoded as a single input hex string prefixed with 0x01
    /// - fields: array of u32 slices, each encoded as a single input hex string (u32 little-endian) prefixed with 0x02
    ///
    /// Returns the proof request id on success.
    pub fn generate_proof(
        &self,
        program_id: &str,
        proof_type: Option<&str>,
        witness: &[&[u8]],
        fields: &[&[u32]],
    ) -> eyre::Result<String> {
        let mut inputs: Vec<String> = Vec::with_capacity(witness.len() + fields.len());

        // Encode witness entries: 0x01 | bytes
        for w in witness {
            inputs.push(encode_witness(w));
        }

        // Encode fields entries: 0x02 | u32 (little-endian bytes)
        for f in fields {
            inputs.push(encode_fields(f));
        }

        let body = ProofRequest { input: inputs };

        //axiom_prove::ProveSdk::generate_new_proof(&self, args)

        unimplemented!();

        let url = format!("{}/v1/proofs", self.base_url.trim_end_matches('/'));
        // let client = reqwest::blocking::Client::new();

        // // Build query
        // let mut query: Vec<(&str, &str)> = vec![("program_id", program_id)];
        // if let Some(pt) = proof_type { query.push(("proof_type", pt)); }

        // let resp = client
        //     .post(url)
        //     .header("Axiom-API-Key", &self.api_key)
        //     .query(&query)
        //     .json(&body)
        //     .send()?;

        // if resp.status().is_success() {
        //     let pr: ProofResponse = resp.json()?;
        //     Ok(pr.id)
        // } else {
        //     let status = resp.status();
        //     let text = resp.text().unwrap_or_default();
        //     Err(AxiomError::Http(format!("status {}: {}", status, text)))
        // }
    }
}

#[derive(Serialize)]
struct ProofRequest {
    input: Vec<String>,
}

#[derive(Deserialize)]
struct ProofResponse {
    id: String,
}

fn encode_witness(w: &[u8]) -> String {
    let mut buf = Vec::with_capacity(1 + w.len());
    buf.push(0x01);
    buf.extend_from_slice(w);
    format!("0x{}", hex::encode(buf))
}

fn encode_fields(f: &[u32]) -> String {
    let mut buf = Vec::with_capacity(1 + f.len() * 4);
    buf.push(0x02);
    for &v in f {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    format!("0x{}", hex::encode(buf))
}

// Custom deserializer: decode hex string (no 0x prefix) into bytes.
fn hex_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    hex::decode(&s).map_err(serde::de::Error::custom)
}

#[derive(serde::Deserialize)]
struct AxiomStarkProof {
    #[serde(deserialize_with = "hex_to_bytes")]
    proof: Vec<u8>,
    #[serde(deserialize_with = "hex_to_bytes")]
    user_public_values: Vec<u8>,
    version: String,
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_witness() {
        let w = b"ABC"; // 41 42 43
        let s = encode_witness(w);
        assert_eq!(s, "0x01414243");
    }

    #[test]
    fn test_encode_fields() {
        let f: &[u32] = &[0x1, 0xA0B0C0D0];
        let s = encode_fields(f);
        // 0x02 | 01 00 00 00 | D0 C0 B0 A0
        assert_eq!(s, "0x0201000000d0c0b0a0");
    }

    #[test]
    fn test_decode_axiom_stark_proof_from_file() {
        let _ = scroll_zkvm_types::proof::StarkProof::read_from_axiom_cloud(Path::new("./testdata/axiom/stark-proof.json")).unwrap();

    }
}
