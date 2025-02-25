use std::marker::PhantomData;

use base64::{Engine, prelude::BASE64_STANDARD};
use openvm_native_recursion::halo2::EvmProof;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Visitor, ser::SerializeStruct};
use snark_verifier_sdk::snark_verifier::{
    halo2_base::halo2_proofs::halo2curves::bn256::Fr, util::arithmetic::PrimeField,
};

use crate::proof::{RootProof, WrappedProof};

/// Scroll's proof format from the legacy code base in [zkevm_circuits][zkevm_circuits] must be
/// implemented for a generic [`WrappedProof`] type, which is achieved by implementing [`Serialize`]
/// and [`Deserialize`] for it.
///
/// In order to do so, we must pick some values from the proofs ([`RootProof`] or [`EvmProof`]),
/// namely, instances and the proof itself. The proof bytes must then be encoded to base64 format.
///
/// [zkevm_circuits]: https://github.com/scroll-tech/zkevm_circuits
pub trait LegacyProofFormat: Sized {
    /// Spit out the proof bytes.
    fn proof<E: serde::ser::Error>(&self) -> Result<Vec<u8>, E>;

    /// Flatten and serialise the instances for an [`EvmProof`]. For the [`RootProof`] this is an
    /// empty vector.
    fn instances(&self) -> Vec<u8>;

    /// Given the proof and instances bytes, deserialise the inner proof type itself.
    fn deserialize<E: serde::de::Error>(proof: &[u8], instances: &[u8]) -> Result<Self, E>;
}

impl LegacyProofFormat for RootProof {
    fn proof<E: serde::ser::Error>(&self) -> Result<Vec<u8>, E> {
        bincode::serialize(&self).map_err(serde::ser::Error::custom)
    }

    fn instances(&self) -> Vec<u8> {
        vec![]
    }

    fn deserialize<E: serde::de::Error>(proof: &[u8], instances: &[u8]) -> Result<Self, E> {
        if !instances.is_empty() {
            return Err(serde::de::Error::custom(
                "RootProof does not have instances",
            ));
        }

        bincode::deserialize(proof).map_err(serde::de::Error::custom)
    }
}

impl LegacyProofFormat for EvmProof {
    fn proof<E: serde::ser::Error>(&self) -> Result<Vec<u8>, E> {
        Ok(self.proof.to_vec())
    }

    fn instances(&self) -> Vec<u8> {
        self.instances[0]
            .iter()
            .flat_map(|fr| fr.to_bytes().into_iter().rev())
            .collect()
    }

    fn deserialize<E: serde::de::Error>(proof: &[u8], instances: &[u8]) -> Result<Self, E> {
        if instances.len() % 32 != 0 {
            return Err(serde::de::Error::custom(
                "EvmProof expects instances in chunk of 32 elements",
            ));
        }

        let instances = vec![
            instances
                .chunks_exact(32)
                .map(|fr_be| {
                    Fr::from_repr({
                        let mut fr_le: [u8; 32] = fr_be
                            .try_into()
                            .expect("instances.len() % 32 == 0 has already been asserted");
                        fr_le.reverse();
                        fr_le
                    })
                    .expect("Fr::from_repr failed")
                })
                .collect(),
        ];

        Ok(Self {
            instances,
            proof: proof.to_vec(),
        })
    }
}

impl<Metadata, Proof> Serialize for WrappedProof<Metadata, Proof>
where
    Metadata: Serialize,
    Proof: LegacyProofFormat,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut wrapped_proof = serializer.serialize_struct("WrappedProof", 5)?;

        // 1. Metadata
        wrapped_proof.serialize_field("metadata", &self.metadata)?;

        // 2. Proof bytes as base64-encoded.
        let proof = {
            let proof = self
                .proof
                .proof::<S::Error>()
                .map_err(serde::ser::Error::custom)?;
            BASE64_STANDARD.encode(proof)
        };
        wrapped_proof.serialize_field("proof", &proof)?;

        // 3. Instances (in case of EvmProof).
        let instances = {
            let instances = self.proof.instances();
            BASE64_STANDARD.encode(instances)
        };
        wrapped_proof.serialize_field("instances", &instances)?;

        // 4. Verifying key.
        let vk = BASE64_STANDARD.encode(&self.vk);
        wrapped_proof.serialize_field("vk", &vk)?;

        // 5. git ref.
        wrapped_proof.serialize_field("git_version", &self.git_version)?;

        wrapped_proof.end()
    }
}

impl<'de, Metadata, Proof> Deserialize<'de> for WrappedProof<Metadata, Proof>
where
    Metadata: Deserialize<'de>,
    Proof: LegacyProofFormat,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Metadata,
            Proof,
            Instances,
            Vk,
            GitVersion,
        }

        struct WrappedProofVisitor<Metadata, Proof> {
            _metadata: PhantomData<Metadata>,
            _proof: PhantomData<Proof>,
        }

        impl<'de, Metadata, Proof> Visitor<'de> for WrappedProofVisitor<Metadata, Proof>
        where
            Metadata: Deserialize<'de>,
            Proof: LegacyProofFormat,
        {
            type Value = WrappedProof<Metadata, Proof>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct WrappedProof")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let metadata = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let proof = {
                    let proof: String = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    BASE64_STANDARD
                        .decode(proof.as_bytes())
                        .map_err(serde::de::Error::custom)?
                };
                let instances = {
                    let instances: String = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                    BASE64_STANDARD
                        .decode(instances.as_bytes())
                        .map_err(serde::de::Error::custom)?
                };
                let vk = {
                    let vk: String = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                    BASE64_STANDARD
                        .decode(vk.as_bytes())
                        .map_err(serde::de::Error::custom)?
                };
                let git_version = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;

                let proof = <Proof as LegacyProofFormat>::deserialize(&proof, &instances)?;

                Ok(WrappedProof {
                    metadata,
                    proof,
                    vk,
                    git_version,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut metadata = None;
                let mut proof = None;
                let mut instances = None;
                let mut vk = None;
                let mut git_version = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Metadata => {
                            if metadata.is_some() {
                                return Err(serde::de::Error::duplicate_field("metadata"));
                            }
                            metadata = Some(map.next_value()?);
                        }
                        Field::Proof => {
                            if proof.is_some() {
                                return Err(serde::de::Error::duplicate_field("proof"));
                            }
                            proof = Some(map.next_value()?);
                        }
                        Field::Instances => {
                            if instances.is_some() {
                                return Err(serde::de::Error::duplicate_field("instances"));
                            }
                            instances = Some(map.next_value()?);
                        }
                        Field::Vk => {
                            if vk.is_some() {
                                return Err(serde::de::Error::duplicate_field("vk"));
                            }
                            vk = Some(map.next_value()?);
                        }
                        Field::GitVersion => {
                            if git_version.is_some() {
                                return Err(serde::de::Error::duplicate_field("git_version"));
                            }
                            git_version = Some(map.next_value()?);
                        }
                    }
                }

                let metadata =
                    metadata.ok_or_else(|| serde::de::Error::missing_field("metadata"))?;
                let proof: Vec<u8> = {
                    let proof: String =
                        proof.ok_or_else(|| serde::de::Error::missing_field("proof"))?;
                    BASE64_STANDARD
                        .decode(proof.as_bytes())
                        .map_err(serde::de::Error::custom)?
                };
                let instances: Vec<u8> = {
                    let instances: String =
                        instances.ok_or_else(|| serde::de::Error::missing_field("instances"))?;
                    BASE64_STANDARD
                        .decode(instances.as_bytes())
                        .map_err(serde::de::Error::custom)?
                };
                let vk = {
                    let vk: String = vk.ok_or_else(|| serde::de::Error::missing_field("vk"))?;
                    BASE64_STANDARD
                        .decode(vk.as_bytes())
                        .map_err(serde::de::Error::custom)?
                };
                let git_version =
                    git_version.ok_or_else(|| serde::de::Error::missing_field("git_version"))?;

                let proof = <Proof as LegacyProofFormat>::deserialize(&proof, &instances)?;

                Ok(WrappedProof {
                    metadata,
                    proof,
                    vk,
                    git_version,
                })
            }
        }

        const FIELDS: &[&str] = &["metadata", "proof", "instances", "vk", "git_version"];
        deserializer.deserialize_struct("WrappedProof", FIELDS, WrappedProofVisitor {
            _metadata: PhantomData,
            _proof: PhantomData,
        })
    }
}
