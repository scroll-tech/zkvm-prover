pub mod commitments;

pub mod evm;

pub mod verifier;

#[cfg(test)]
mod test {
    use scroll_zkvm_types::{proof::ProofEnum, utils::vec_as_base64};
    use std::path::Path;

    #[derive(Clone, serde::Deserialize)]
    pub struct WrappedProof {
        pub proof: ProofEnum,
        #[serde(with = "vec_as_base64", default)]
        pub vk: Vec<u8>,
    }

    impl WrappedProof {
        pub fn from_json(path: impl AsRef<Path>) -> eyre::Result<Self> {
            let fd = std::fs::File::open(path)?;
            let reader = std::io::BufReader::new(fd);
            let ret: WrappedProof = serde_json::from_reader(reader)?;
            Ok(ret)
        }
    }
}
