use openvm_native_recursion::hints::Hintable;
use openvm_sdk::StdIn;
use scroll_zkvm_types::{public_inputs::ForkName, task::ProvingTask as UniversalProvingTask};

pub mod batch;

pub mod chunk;

pub mod bundle;

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask: serde::de::DeserializeOwned {
    fn identifier(&self) -> String;

    fn build_guest_input_inner(&self, stdin: &mut StdIn) -> Result<(), rkyv::rancor::Error>;

    fn build_guest_input(&self) -> Result<StdIn, rkyv::rancor::Error> {
        let mut stdin = StdIn::default();
        self.build_guest_input_inner(&mut stdin)?;
        Ok(stdin)
    }

    fn fork_name(&self) -> ForkName;
}

impl ProvingTask for UniversalProvingTask {
    fn identifier(&self) -> String {
        self.identifier.clone()
    }

    fn build_guest_input_inner(&self, stdin: &mut StdIn) -> Result<(), rkyv::rancor::Error> {
        for witness in &self.serialized_witness {
            stdin.write_bytes(witness);
        }

        for proof in &self.aggregated_proofs {
            let streams = if self.fork_name() >= ForkName::Feynman {
                proof.proofs[0].write()
            } else {
                proof.write()
            };
            for s in &streams {
                stdin.write_field(s);
            }
        }
        Ok(())
    }

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }
}
/// Read the 'GUEST_VERSION' from the environment variable.
/// Mainly used for testing purposes to specify the guest version
pub fn guest_version() -> Option<ForkName> {
    std::env::var("GUEST_VERSION").ok().and_then(|v| {
        if v.is_empty() {
            None
        } else {
            Some(ForkName::from(v.as_str()))
        }
    })
}
