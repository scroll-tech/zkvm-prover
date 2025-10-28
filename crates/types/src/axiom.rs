
use serde::Serialize;
use openvm_native_recursion::hints::Hintable;
use openvm_sdk::SC;
use openvm_stark_sdk::{
    openvm_stark_backend::{p3_field::PrimeField32, proof::Proof},
    p3_baby_bear::BabyBear,
};
use std::path::Path;

#[derive(Clone, Default)]
pub struct AxiomInput {
    pub raw_bytes: Vec<Vec<u8>>,
    pub fields: Vec<Vec<BabyBear>>,
}

/// Custom serializer to match Axiom POST /v1/proofs expected body as raw array: ["0x..."]
impl Serialize for AxiomInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;

        // Build inputs: all raw_bytes as 0x01|bytes, plus all fields as 0x02|u32 
        let mut inputs: Vec<String> = Vec::with_capacity(self.raw_bytes.len() + self.fields.len());

        // Encode witness entries (0x01 | bytes)
        for w in &self.raw_bytes {
            let mut buf = Vec::with_capacity(1 + w.len());
            buf.push(0x01);
            buf.extend_from_slice(w);
            inputs.push(format!("0x{}", hex::encode(&buf)));
        }

        // Encode fields as 0x02 | u32 LE bytes
        for fs in &self.fields {
            let mut buf = Vec::with_capacity(1 + 4*fs.len());
            buf.push(0x02);
            for f in fs {
                let v: u32 = f.as_canonical_u32();
                buf.extend_from_slice(&v.to_le_bytes());
            }
            inputs.push(format!("0x{}", hex::encode(&buf)));
        }

        let mut seq = serializer.serialize_seq(Some(inputs.len()))?;
        for s in inputs {
            seq.serialize_element(&s)?;
        }
        seq.end()
    }
}


impl super::ProvingTask {
    pub fn build_to_axiom_input(&self) -> AxiomInput {

        let fields = self.aggregated_proofs.iter()
            .map(|proof|proof.proofs[0].write())
            .reduce(|mut v1, mut v2|{
                v1.append(&mut v2);
                v1
            }).unwrap_or_default();

        AxiomInput {
            raw_bytes: self.serialized_witness.clone(),
            fields,
        }

    }
}

impl super::proof::StarkProof {
    pub fn read_from_axiom_cloud<P: AsRef<Path>>(path: P) -> eyre::Result<Self> {
        use openvm_sdk::{types::VersionedVmStarkProof, codec::Decode};
        use std::io::Cursor;
        let data = std::fs::read_to_string(&path)?;
        let proof: VersionedVmStarkProof = serde_json::from_str(&data)?;
        
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