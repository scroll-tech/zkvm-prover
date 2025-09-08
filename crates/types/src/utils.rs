pub use types_base::utils::*;

pub mod vec_as_base64 {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD.encode(v);
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let base64 = String::deserialize(d)?;
        BASE64_STANDARD
            .decode(base64.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

pub mod as_base64 {
    use base64::prelude::*;
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::DeserializeOwned};

    pub fn serialize<S: Serializer, T: Serialize>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        let v_bytes = bincode_v1::serialize(v).map_err(serde::ser::Error::custom)?;
        let v_base64 = BASE64_STANDARD.encode(&v_bytes);
        String::serialize(&v_base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, T: DeserializeOwned>(
        d: D,
    ) -> Result<T, D::Error> {
        let v_base64 = String::deserialize(d)?;
        let v_bytes = BASE64_STANDARD
            .decode(v_base64.as_bytes())
            .map_err(serde::de::Error::custom)?;
        bincode_v1::deserialize(&v_bytes).map_err(serde::de::Error::custom)
    }
}

pub mod serialize_vk {
    use types_base::aggregation::ProgramCommitment;
    pub fn deserialize(commitment_bytes: &[u8]) -> ProgramCommitment {
        let mut exe: [u32; 8] = [0; 8];
        for (i, bytes4) in commitment_bytes[..32].chunks(4).enumerate() {
            let bytes: [u8; 4] = bytes4.try_into().unwrap();
            exe[i] = u32::from_le_bytes(bytes);
        }

        let mut vm: [u32; 8] = [0; 8];
        for (i, bytes4) in commitment_bytes[32..].chunks(4).enumerate() {
            let bytes: [u8; 4] = bytes4.try_into().unwrap();
            vm[i] = u32::from_le_bytes(bytes);
        }
        ProgramCommitment { exe, vm }
    }

    pub fn serialize(commit: &ProgramCommitment) -> Vec<u8> {
        commit
            .exe
            .iter()
            .chain(commit.vm.iter())
            .flat_map(|u| u.to_le_bytes().into_iter())
            .collect()
    }
}

pub mod point_eval {
    pub use types_batch::utils::point_eval::*;
}
