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
