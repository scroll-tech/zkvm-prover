use serde::{Deserialize, Serialize};

/// Input structure for OpenVM input json
///
/// ```json
/// {
///   "input": [ "0x...", "0x...", ... ]
/// }
/// ```
///
/// Reference: https://github.com/openvm-org/openvm/blob/7e9488992a74d49fa697359681cd2a7e768b90ef/crates/cli/src/input.rs#L82-L115
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct OpenVMInput {
    input: Vec<String>,
}

impl super::ProvingTask {
    pub fn build_openvm_input(&self) -> OpenVMInput {
        let mut input = Vec::new();

        // Encode witness entries (0x01 | bytes)
        for w in self.serialized_witness.iter() {
            let mut buf = Vec::with_capacity(1 + w.len());
            buf.push(0x01);
            buf.extend_from_slice(w);
            input.push(format!("0x{}", hex::encode(&buf)));
        }

        // Encode proof bytes using v2 Encode trait
        use openvm_stark_sdk::openvm_stark_backend::codec::Encode;
        for proof in &self.aggregated_proofs {
            let encoded = proof.proof.encode_to_vec().expect("proof encode failed");
            let mut buf = Vec::with_capacity(1 + encoded.len());
            buf.push(0x02);
            buf.extend_from_slice(&encoded);
            input.push(format!("0x{}", hex::encode(&buf)));
        }

        OpenVMInput { input }
    }
}
