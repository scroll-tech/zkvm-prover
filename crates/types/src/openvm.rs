use openvm_native_recursion::hints::Hintable;
use openvm_sdk::SC;
use openvm_sdk::codec::Decode;
use openvm_sdk::types::VersionedVmStarkProof;
use openvm_stark_sdk::{
    openvm_stark_backend::{p3_field::PrimeField32, proof::Proof},
    p3_baby_bear::BabyBear,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::io::Cursor;

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

impl TryFrom<VersionedVmStarkProof> for super::proof::StarkProof {
    type Error = io::Error;

    fn try_from(proof: VersionedVmStarkProof) -> io::Result<Self> {
        let inner_proof = Proof::<SC>::decode_from_bytes(&proof.proof)?;
        let mut pv_reader = Cursor::new(proof.user_public_values);
        // decode_vec is not pub so we have to use the detail inside it ...
        let len = usize::decode(&mut pv_reader)?;
        let mut public_values = Vec::with_capacity(len);

        for _ in 0..len {
            public_values.push(BabyBear::decode(&mut pv_reader)?);
        }

        Ok(Self {
            proofs: vec![inner_proof],
            public_values,
            stat: Default::default(),
        })
    }
}
