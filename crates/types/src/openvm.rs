use openvm_native_recursion::hints::Hintable;
use openvm_stark_sdk::openvm_stark_backend::p3_field::PrimeField32;
use serde::{Deserialize, Serialize};

/// Input structure for OpenVM input json
///
/// ```json
/// {
///   "input": [ "0x...", "0x...", ... ]
/// }
/// ```
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

        // Encode proof fields (0x02 | u32_le_bytes...)
        for field in self
            .aggregated_proofs
            .iter()
            .flat_map(|proof| proof.proofs[0].write())
        {
            let mut buf = Vec::with_capacity(1 + 4 * field.len());
            buf.push(0x02);
            for f in field {
                let v: u32 = f.as_canonical_u32();
                buf.extend_from_slice(&v.to_le_bytes());
            }
            input.push(format!("0x{}", hex::encode(&buf)));
        }

        OpenVMInput { input }
    }
}
