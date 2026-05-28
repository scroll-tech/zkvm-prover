use openvm_sdk::StdIn;
use scroll_zkvm_types::{public_inputs::ForkName, task::ProvingTask as UniversalProvingTask};

/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
/// Every proving task must have an identifier. The identifier will be appended to a prefix while
/// storing/reading proof to/from disc.
pub trait ProvingTask: serde::de::DeserializeOwned {
    fn identifier(&self) -> String;

    fn build_guest_input_inner(&self, stdin: &mut StdIn);

    fn build_guest_input(&self) -> StdIn {
        let mut stdin = StdIn::default();
        self.build_guest_input_inner(&mut stdin);
        stdin
    }

    fn fork_name(&self) -> ForkName;
}

impl ProvingTask for UniversalProvingTask {
    fn identifier(&self) -> String {
        self.identifier.clone()
    }

    fn build_guest_input_inner(&self, stdin: &mut StdIn) {
        for witness in &self.serialized_witness {
            stdin.write_bytes(witness);
        }

        // Write input commits for deferred STARK verification (v2).
        // The guest reads these via openvm::io::read() before calling deferred_compute.
        // Must use stdin.write (openvm serde) to match guest deserialization format.
        if !self.input_commits.is_empty() {
            stdin.write(&self.input_commits);
        }
    }

    fn fork_name(&self) -> ForkName {
        ForkName::from(self.fork_name.as_str())
    }
}
